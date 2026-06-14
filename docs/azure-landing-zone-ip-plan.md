# Azure Landing Zone – IP Addressing Scheme & Network Security Design

## Document Control
- **Version:** 5.2
- **Created:** 2025-07-04
- **Last updated:** 2026-06-14

---

## 1. Design Principles

| Principle | Implementation |
|-----------|----------------|
| Segmentation | Separate subnets per function; NSGs enforce micro-segmentation |
| Zero Trust | All inter-zone traffic inspected by NVAs; no direct spoke-to-spoke or spoke-to-internet. Two documented, deliberate exceptions: intra-hub Shared Services → Hub PE (system route, Section 11.3) and on-prem → Hub PE (direct, Section 11.3), compensating controls are the PE NSG + `privateEndpointNetworkPolicies = Enabled`. |
| Scalability | /12 master block supports 1M+ addresses |
| Symmetry | ILB + UDR + SNAT ensure same NVA handles request and response |
| High Availability | NVAs behind Standard ILBs with HA ports |
| Defence in Depth | NSG + NVA + Azure Firewall (optional) layered controls |

### 1.1 SKU Assumptions

Behaviour, sizing constraints, and supported features vary significantly by SKU. This design assumes the following SKUs. **Adjust to your environment and re-verify constraints before deployment.**

| Service | Assumed SKU | Rationale / SKU-specific behaviour referenced in this document |
|---|---|---|
| Internal Load Balancer | **Standard** | HA Ports, Floating IP, AZ support, all required by this design (Section 5, 6.3, 6.4). Basic is EOL for new deployments. |
| Azure Bastion | **Standard** | The port-80 outbound NSG rule (`AllowHttpOutbound`, Section 9.1) is a base requirement on the MS NSG page for **all** SKUs, it is used for session/certificate validation and is not SKU-gated. Standard is assumed here because custom RDP/SSH ports, native client, and shareable links require it; Basic does not support them. |
| VPN Gateway | **VpnGw2AZ** or higher | Zone-redundant, active-active, BGP capable. Required if VPN is the primary hybrid path. |
| ExpressRoute Gateway | **ErGw2AZ** or higher | Zone-redundant, higher throughput. Note **ErGw2AZ does not support FastPath at all**: FastPath requires ErGw3AZ, Ultra Performance, or ErGwScale (≥10 scale units). This is convenient here: **FastPath MUST NOT be enabled anyway** while DNS Private Resolver handles on-prem → PE resolution (Section 3.2.1, FastPath is incompatible with Private Resolver). If you later upgrade to ErGw3AZ for bandwidth, keep FastPath off or move resolution to VM-based forwarders first. |
| Azure Firewall | **Premium** (if deployed) | This design treats Azure Firewall as optional (subnets reserved in Section 3.1). If deployed, Premium is assumed for TLS inspection and IDPS. SNAT behaviour (Section 6.5) is SKU-agnostic per MS docs. |
| Azure Route Server | **Single SKU** | Subnet is reserved in Section 3.1. Deployment is optional, only required when dynamic route exchange with NVAs is needed. Route Server FAQ constraints apply (Section 12.2). |
| DNS Private Resolver | **Single PaaS tier** | No SKU variants. Zone-redundant by default. |
| Third-party NVAs (NS + EW) | **Vendor-specific** | Each NVA has **2 data-plane NICs (External + Internal) plus an out-of-band management NIC** (Section 6.1). Vendor must support HA-port aware back-end pool membership, SNAT via internal NIC IP, and loopback IP configuration (Section 6.4). |
| Azure DDoS Protection | **Network Protection** (single plan) | **v5.0 (CAF)**: one plan deployed in the **Connectivity subscription**, associated to the Hub VNet and every spoke VNet, protects all public-IP resources (NS NVA PIPs, Bastion, Route Server) and includes 100 public IPs in the base price. Per [traditional Azure networking topology](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/traditional-azure-networking-topology): deploy a single plan in the connectivity subscription and use it for all landing-zone and platform VNets. Also satisfies the Section 12.2 Route Server DDoS guardrail. |

> **Upgrade path note**: if any SKU above is downgraded (e.g., Bastion Basic), re-review Sections 9.1 and 6.4, specific rules and features may no longer apply.

### 1.2 CAF / Azure Landing Zone Alignment (v5.0)

This design is the **network topology and connectivity design area** of an Azure Landing Zone. v5.0 aligns it explicitly with the Cloud Adoption Framework pages fetched 2026-06-11: [What is an Azure landing zone?](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/), [Design principles](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/design-principles), [Network topology and connectivity](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/design-area/network-topology-and-connectivity), [Define an Azure network topology](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/define-an-azure-network-topology), [Traditional Azure networking topology](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/traditional-azure-networking-topology), and [Plan for IP addressing](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/plan-for-ip-addressing).

#### 1.2.1 Topology Decision Record: why traditional hub-and-spoke, not Virtual WAN

Per *Define an Azure network topology*, the traditional customer-managed topology is the right fit when **all** of the following hold, and they do here:

| CAF criterion (traditional topology) | This design |
|---|---|
| Resources in one (or a few) Azure regions; no full-mesh global transit needed | Single region today; two-region template defined (Section 2.1) |
| Fewer than ~30 IPsec site-to-site tunnels per region | ExpressRoute is the primary hybrid path; VPN is backup only |
| Full control and granularity over routing policy | The entire design is granular UDR + NSG control (Sections 7-9) |
| Dependency on centralized NVAs and granular routing | Dual-tier NS/EW third-party NVAs are the security core |

**Re-evaluation triggers** (migrate to a Virtual WAN-based topology when any becomes true): hub-and-spoke needed across **more than two** Azure regions with global transit between landing zones; **> 30** branch sites needing native IPsec termination / large-scale SD-WAN integration; or required **VPN ↔ ExpressRoute transitive routing** at a scale where hub Route Server + NVA management overhead exceeds the value of full control.

#### 1.2.2 Subscription & management-group mapping (ALZ reference architecture)

VNets cannot span subscriptions; peering crosses them. The mapping below follows the ALZ conceptual architecture (Platform vs Application landing zones; Connectivity / Corp / Online management groups):

| ALZ construct | What lands there in this design |
|---|---|
| **Connectivity subscription** (Platform LZ, Connectivity MG) | The **Hub VNet** and everything in it: GatewaySubnet (ER/VPN gateways), Route Server, reserved Azure Firewall subnets, Bastion, NS/EW NVAs + ILBs, NVA management, Hub PE subnet, Shared-Services and Management /19 sections, **DNS Private Resolver + every `privatelink.*` Private DNS zone**, and the **single DDoS Network Protection plan**. |
| **Identity** (Platform LZ) | The AD DS Domain Controllers (Subnet-DomainControllers `10.0.33.0/24`). CAF permits DCs either in the central hub ("If necessary, also deploy Active Directory domain controllers and DNS servers", traditional-topology page) or in a dedicated Identity-subscription VNet peered to the hub. **This design keeps them in the hub VNet** for DNS/latency simplicity; if your operating model requires Identity-subscription ownership, carve a peered Identity VNet from the platform-growth space (Section 2) and move `10.0.33.0/24` semantics there, routes/NSGs in this document transfer unchanged. |
| **Management subscription** (Platform LZ) | The PaaS management estate (Log Analytics, Azure Automation accounts, Recovery Services vaults, Update Manager). Their **network touchpoints**: private endpoints and any management VMs, live in the hub's Management /19 subnets (Section 3.3), which physically sit in the Connectivity subscription because they share the Hub VNet. |
| **Corp management group** (Application LZs) | Every Prod/Dev/Test **spoke VNet** in this plan: internal-facing, hub-routed, no direct Internet exposure. One application landing zone (subscription) per workload **per environment**, vended with a spoke from the Section 4 pools. |
| **Online management group** (Application LZs) | Public-facing workloads. Pattern: an Online spoke peers to the hub like any Corp spoke for east-west/egress, but its **inbound** L7 path is its own **Application Gateway (with WAF) deployed inside the spoke**: per CAF, L7 inbound NVAs are *not* shared hub services (Section 5 inbound note). Azure Front Door fronts multi-region/global entry. |
| **Policy inheritance** | Spokes inherit ALZ policy assignments from their MG (Corp/Online); Section 12.7 lists the network guardrails this document expects as policy-as-code. |

#### 1.2.3 Design-principles alignment & deviation register

| ALZ design principle | How this design implements it |
|---|---|
| **Subscription democratization** | Spokes are vended per workload per environment from pre-planned, non-overlapping pools using the **T-shirt catalog** (Section 4.1.1) and IPAM API integration (Section 4.4), application teams self-serve address space without platform-team bottlenecks. |
| **Policy-driven governance** | Network invariants are enforced as Azure Policy + Terraform plan gates, not tribal knowledge: Section 12.7 catalog + the fact-check report's Section L checks. |
| **Single control and management plane** | Everything here is ARM-native (VNets, UDRs, NSGs, peering, DNS) managed via IaC (AVM Terraform/Bicep); **Azure Virtual Network Manager** is the sanctioned at-scale option for peering/security-admin configuration, and **Network Watcher network insights/topology** for monitoring, no custom portals. |
| **Application-centric service model** | One spoke = one application landing zone; environments (Dev/Test/Prod) are separated by **subscription + spoke pool**, identical NSG/RT semantics across environments (Section 4.2/Section 4.2.1) so promotion testing exercises production security behaviour. |
| **Azure-native design alignment** | **Documented deviation**: third-party NVAs are used instead of Azure Firewall for NS/EW inspection (vendor feature requirements: TLS inspection depth, vendor SD-WAN integration, existing operational expertise). The native exit ramp is pre-provisioned, `AzureFirewallSubnet` + `AzureFirewallManagementSubnet` are reserved (Section 3.1) and Section 6.5/Section 12.3 already document Azure Firewall SNAT/UDR behaviour, so replacing NVAs with Azure Firewall Premium is a routing cut-over, not a re-design. |

---

## 2. Master IP Allocation

> **v5.0 reframing (CAF)**: per [Plan for IP addressing](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/plan-for-ip-addressing), IP space must be planned **in advance, per region, non-overlapping with every other Azure region and every on-premises location**. The master `/12` is therefore now expressed as a **regional /13 template**: each region receives one `/13` with an identical internal layout. The v4.9 allocations are unchanged, they *are* Region 1; v5.0 makes the regional pattern they already formed explicit.

| Block | CIDR | Purpose |
|-------|------|---------|
| Master | `10.0.0.0/12` | All Azure Landing Zone networks, capacity for **exactly two regional /13s** |
| **Region 1** | `10.0.0.0/13` | Primary region (this document) |
| ├─ Platform Landing Zone | `10.0.0.0/16` | Hub VNet sections, shared services, management (Section 3) |
| ├─ Reserved, Platform growth | `10.1.0.0/16`, `10.2.0.0/15` | Held contiguous with the Platform /16 so platform expansion (second hub VNet, Identity VNet per Section 1.2.2, or hub address-space additions) summarises as `10.0.0.0/14` without renumbering. Do not assign to spokes. |
| └─ Application Landing Zones | `10.4.0.0/14` | Spoke pools, Prod, Dev, Test (Section 4) |
| **Region 2 (reserved)** | `10.8.0.0/13` | Secondary region, deploy with the **identical internal template** (Platform `10.8.0.0/16`, growth `10.9.0.0/16` + `10.10.0.0/15`, spokes `10.12.0.0/14`). Formerly labelled "Future Expansion". |
| Region 3+ | *(new block required)* | The /12 is fully consumed by two regions. Allocate the next region from a **new, non-overlapping** RFC 1918 block (e.g., `10.16.0.0/12`) reserved in IPAM (Section 4.4) before any Region-3 work begins. |

### 2.1 Multi-region growth rules (CAF traditional-topology guidance)

1. **Two regions**: connect Region 1 ↔ Region 2 with **global VNet peering between the hub VNets**. Hub-to-hub traffic bypasses neither region's EW NVAs unless routed to them, add hub UDRs for the remote region's spoke `/14` pointing at the **local** EW ILB if cross-region inspection is required.
2. **Spoke route tables already comply** with the CAF cross-region inspection mitigation: `RT-Spoke-Workloads` has **BGP propagation disabled** (Section 8), so remote-region spoke prefixes never silently appear in spoke effective routes via ExpressRoute, cross-region reachability is granted only by explicit UDR (`10.12.0.0/14 → 10.0.5.100` in Region-1 spokes), keeping the firewall in path.
3. **More than two regions**: per CAF, prefer connecting every regional hub to the **same ExpressRoute circuits**, or re-evaluate **Virtual WAN** (Section 1.2.1 triggers), global peering at >2 regions multiplies peering relationships and UDR complexity.
4. Place each region's hub resources in **region-scoped resource groups**, and manage cross-region connectivity/security configuration with **Azure Virtual Network Manager** rather than hand-built peering meshes.

### 2.2 Address-space hygiene (CAF hard rules)

- **RFC 1918 only.** Never assign, route, or NAT-translate into: `224.0.0.0/4` (multicast), `255.255.255.255/32` (broadcast), `127.0.0.0/8` (loopback), `169.254.0.0/16` (link-local), `168.63.129.16/32` (Azure internal DNS / WireServer). Never use public IP ranges your organization does not own.
- **On-prem overlap gate (pre-deployment)**: validate that `<on-prem-supernet>` (and every individually advertised on-prem prefix) does **not** intersect `10.0.0.0/12`. If a legacy/acquired site overlaps unavoidably, the sanctioned escape hatch is **NAT on the VPN gateway** (GA on standalone VPN Gateway and Virtual WAN) for that site only, do not renumber the Azure side around one site.
- **Address-space changes are online operations**: a VNet's address space can be extended after creation without outage; each existing peering then requires a **resync** ([update peering address space](https://learn.microsoft.com/en-us/azure/virtual-network/update-virtual-network-peering-address-space)). This is the designed growth mechanism for the Hub VNet (Section 3.0), budget the resync into the change window for environments with hundreds of spoke peerings.
- **IPv4 exhaustion levers** (only if the /12 ever runs short): CAF's [nonroutable landing-zone spoke pattern + Private Link service](https://learn.microsoft.com/en-us/azure/architecture/networking/guide/internet-protocol-version-4-exhaustion) lets new spokes reuse overlapping space and expose services via Private Link, adopt per-workload, never retrofit onto routed spokes.

### 2.3 IPv6 stance (v5.0)

This design is **IPv4-only by decision**, re-evaluated per workload: the platform itself constrains dual-stack adoption (DNS Private Resolver does not support IPv6-enabled subnets Section 3.2.1; Route Server has IPv6 caveats Section 12.2; IPv6 subnets must be exactly `/64`). When IPv6-only **clients** must be served before the platform goes dual-stack, use the CAF-documented edge patterns, **Azure Front Door** (L7, proxies IPv6 clients to IPv4 backends) or a **dual-stack NVA gateway in VMSS Flex behind a public Standard LB** (L4), keeping the backend IPv4-only. If/when dual-stack is adopted: VNets gain a single IPv6 CIDR alongside IPv4 (IPv4 can never be disabled), route tables gain IPv6 routes toward the gateways, and every NSG in Section 9 gains mirrored IPv6 rules.

---

## 3. Platform Landing Zone (`10.0.0.0/16` allocation)

> **v5.0 structural change (CAF)**: *Hub VNet address space is no longer the full `/16`.* [Plan for IP addressing](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/plan-for-ip-addressing) is explicit: *"Don't create large virtual networks like `/16`. It ensures that IP address space isn't wasted."* The `10.0.0.0/16` block remains the Platform Landing Zone **plan-level allocation**, but the **Hub VNet is declared with exactly three address prefixes**: the three sections actually in use:
>
> | Hub VNet `addressSpace.addressPrefixes` | Section |
> |---|---|
> | `10.0.0.0/19` | Connectivity (Section 3.1) |
> | `10.0.32.0/19` | Shared Services (Section 3.2) |
> | `10.0.64.0/19` | Management (Section 3.3) |
>
> **24,576 addresses declared instead of 65,536**: and every subnet in Sections 3.1-3.3 falls inside these prefixes, so **nothing is renumbered** (verified computationally, all 21 subnets ⊂ the three /19s). The remaining `10.0.96.0–10.0.255.255` stays **plan-reserved, unassigned**: either a fourth `/19` prefix is *added to the Hub VNet online* when needed (address-space extension is a no-outage operation; each spoke peering then needs a resync, Section 2.2), or it seeds a separate platform VNet (e.g., the Identity VNet option in Section 1.2.2).
>
> **Side-effects, all assessed**: (a) the ER/VPN gateway now advertises **3 hub prefixes** to on-prem instead of 1 (budgeted in Section 15.4); (b) the `VirtualNetwork` NSG service tag for hub NICs narrows to the declared prefixes, no functional change, every rule in Section 9/Section 11 uses literal CIDRs; (c) `RT-Spoke-Workloads`' `To-Hub 10.0.0.0/16 → 10.0.5.100` route is **deliberately kept as the /16 supernet**: UDR prefixes need not match VNet space, and any packet to the unassigned 10.0.96.0+ range is steered to the EW NVA and dropped there (an inspected black-hole, preferable to falling through to the Internet default route).

### 3.1 Connectivity Hub (`10.0.0.0/19`)

| Subnet | CIDR | Usable IPs | Purpose | Route Table | NSG |
|--------|------|------------|---------|-------------|-----|
| GatewaySubnet | `10.0.0.0/26` | 59 | VPN/ExpressRoute Gateways | RT-GatewaySubnet | None (not supported) |
| RouteServerSubnet | `10.0.0.64/26` | 59 | Azure Route Server | None (not supported) | None (not supported) |
| AzureFirewallSubnet | `10.0.0.128/26` | 59 | Azure Firewall (optional) | None | None (not supported) |
| AzureBastionSubnet | `10.0.1.0/26` | 59 | Azure Bastion | None (not supported) | NSG-Bastion (required) |
| Subnet-NS-External | `10.0.2.0/24` | 251 | North-South NVA external NICs | RT-NS-External | NSG-NS-External |
| Subnet-NS-Internal | `10.0.3.0/24` | 251 | North-South NVA internal NICs | RT-NS-Internal | NSG-NS-Internal |
| Subnet-EW-External | `10.0.4.0/24` | 251 | East-West NVA external NICs | RT-EW-External | NSG-EW-External |
| Subnet-EW-Internal | `10.0.5.0/24` | 251 | East-West NVA internal NICs (+ Transit ILB VIP) | RT-EW-Internal | NSG-EW-Internal |
| Subnet-Reserved-Hub | `10.0.6.0/24` | 251 | Reserved (formerly Transit subnet) | - | - |
| Subnet-NVA-Management | `10.0.7.0/24` | 251 | NVA management interfaces | RT-NVA-Mgmt | NSG-NVA-Mgmt |
| Subnet-PrivateEndpoints-Hub | `10.0.8.0/24` | 251 | Private Endpoints (Hub) |, (see note) | NSG-PrivateEndpoints |
| AzureFirewallManagementSubnet | `10.0.0.192/26` | 59 | Azure Firewall Mgmt (reserved for forced tunneling) | None (Azure-managed) | None (not supported) |

> **Architecture Note**: The Transit subnet (`10.0.6.0/24`) from earlier designs has been **removed** and is now reserved for future use. The Transit ILB VIP is now consolidated into `Subnet-EW-Internal` to simplify the architecture and avoid the need for a 3rd NIC on each NVA. See Section 5 for ILB details.

> **v5.2 (F2), chain-segment subnets**: when an inspection tier runs **≥ 2 chained NVA groups** (Section 19), each chained group i ≥ 2 receives a dedicated `/24` internal subnet (`Subnet-NS-Internal-i` / `Subnet-EW-Internal-i`), and a chained East-West/single tier adds one `Subnet-EW-Forward` (`Subnet-FW-Forward`) for group 1's forward NICs. They are allocated **after** `Subnet-PrivateEndpoints-Hub` (from `10.0.9.0/24` upward) so every v5.0 anchor above is unchanged. Single-group tiers (the default) create none of them.

> **v4.9 fix, no route table on Subnet-PrivateEndpoints-Hub**: earlier versions referenced an `RT-PrivateEndpoints` that was never defined anywhere in Section 7. None is needed: Private Endpoints originate no traffic of their own, and **PE return traffic bypasses UDRs** unless `privateEndpointNetworkPolicies` route-table enforcement plus a deliberate UDR pattern is engineered. Associating an empty route table would add an object with zero effect. NSG enforcement (Section 11.3) is retained via `privateEndpointNetworkPolicies = Enabled`.

### 3.2 Shared Services (`10.0.32.0/19`)

> **Important**: This design supports **Azure Private DNS Resolver (PaaS)**, which requires two dedicated delegated subnets. The subnets must be delegated to `Microsoft.Network/dnsResolvers` and cannot host any other resources. NSGs are **omitted** on the DNS Resolver delegated subnets by conservative design choice, current Microsoft docs do not explicitly prohibit them (see Section 3.2.1 and Section 12.5), but the resolver subnets carry only managed-service traffic and an NSG adds risk without benefit here.

| Subnet | CIDR | Usable IPs | Purpose | Route Table | NSG | Delegation |
|--------|------|------------|---------|-------------|-----|------------|
| Subnet-DNS-Inbound | `10.0.32.0/28` | 11 | DNS Resolver Inbound Endpoint | RT-Platform-Workloads | None (not supported) | Microsoft.Network/dnsResolvers |
| Subnet-DNS-Outbound | `10.0.32.16/28` | 11 | DNS Resolver Outbound Endpoint | RT-Platform-Workloads | None (not supported) | Microsoft.Network/dnsResolvers |
| Subnet-DomainControllers | `10.0.33.0/24` | 251 | AD Domain Controllers | RT-Platform-Workloads | NSG-SharedServices | None |
| Subnet-Monitoring | `10.0.34.0/24` | 251 | Log Analytics, monitoring | RT-Platform-Workloads | NSG-SharedServices | None |
| Subnet-KeyVault | `10.0.35.0/24` | 251 | Key Vault Private Endpoints | RT-Platform-Workloads | NSG-SharedServices | None |
| Subnet-JumpServers | `10.0.36.0/24` | 251 | Jump/Admin servers | RT-Platform-Workloads | NSG-JumpServers | None |

#### 3.2.1 Azure Private DNS Resolver Configuration

**Subnet Requirements (per Microsoft Documentation):**
- Minimum subnet size: `/28` (16 IPs)
- Maximum subnet size: `/24` (256 IPs)
- Each endpoint requires its own dedicated subnet
- Subnets must be delegated to `Microsoft.Network/dnsResolvers`
- No other resources can be deployed in delegated subnets
- NSG support on delegated subnets is **not required**; current MS documentation does not explicitly prohibit it, but the conservative practice in this design is to omit NSGs. Validate against [current docs](https://learn.microsoft.com/en-us/azure/dns/dns-private-resolver-overview) at deployment time.
- IPv6-enabled subnets are not supported
- **Incompatible with ExpressRoute FastPath**: if the ExpressRoute Gateway deployed in `GatewaySubnet` has FastPath enabled, on-premises resolution of Azure private DNS zones through the inbound endpoint will not function. Either disable FastPath on the gateway, or use an alternative resolution path (VM-based DNS forwarders or NVA DNS).
- Not compatible with Azure Lighthouse.
- VNet encryption must be disabled on the hosting VNet.
- **Wildcard-rule caveat (v4.9)**: per the [ExpressRoute virtual network gateway documentation](https://learn.microsoft.com/en-us/azure/expressroute/expressroute-about-virtual-network-gateways), a DNS Private Resolver must **not** be deployed in the same VNet as an ExpressRoute gateway when the forwarding ruleset contains a **wildcard (`.`) rule**: gateway management-plane resolution can be disrupted. This design co-locates both in the Hub VNet, so the ruleset must contain **only explicit on-prem domain rules** (e.g., `corp.contoso.com.`), never a catch-all `.` rule. Enforce via policy/review on ruleset changes.

**Endpoint IP Allocation:**
| Endpoint | Subnet | Static IP (Recommended) |
|----------|--------|------------------------|
| Inbound Endpoint | Subnet-DNS-Inbound | `10.0.32.4` |
| Outbound Endpoint | Subnet-DNS-Outbound | `10.0.32.20` |

#### 3.2.2 NVA Firewall Dependency for DNS Resolver Egress

Both DNS Resolver subnets are associated with `RT-Platform-Workloads` (Section 7.6), which routes `0.0.0.0/0 → ILB-NS-Outbound` and `<on-prem-supernet> → ILB-EW-Outbound`. **Any DNS query that egresses the outbound endpoint therefore transits an NVA.** The NVA firewalls must explicitly permit this traffic, otherwise DNS resolution silently fails (query timeout with no useful log trail at the Azure layer).

| Traffic | Source | Destination | Port/Proto | Transits | NVA rule required |
|---|---|---|---|---|---|
| Public DNS fallback (e.g., for non-Azure, non-private domains that the outbound endpoint forwards to a public resolver) | `10.0.32.16/28` (Outbound endpoint) | Internet (typically public DNS such as your on-prem or customer-specified resolver) | UDP/TCP 53 | NS NVA | **Required**: explicit allow on NS NVA for `10.0.32.16/28 → Internet:53/udp,53/tcp` |
| On-premises DNS forwarding (ruleset rule targets on-prem DNS servers) | `10.0.32.16/28` (Outbound endpoint) | `<on-prem-dns-servers>` | UDP/TCP 53 | EW NVA | **Required**: explicit allow on EW NVA for `10.0.32.16/28 → <on-prem-dns>:53/udp,53/tcp` |
| Inbound endpoint receiving queries from on-prem via Gateway | On-prem DNS / clients | `10.0.32.4` (Inbound endpoint) | UDP/TCP 53 | EW NVA (on the ingress path post-RT-GatewaySubnet) | **Required**: explicit allow on EW NVA for `<on-prem-dns> → 10.0.32.4:53/udp,53/tcp` |

> **Operational note**: NVA rule definition is **out of scope** for this IP plan, but the dependency must be flagged in the NVA runbook / Terraform policy module. Failure mode is silent: DNS queries time out with NXDOMAIN or SERVFAIL at the client; the Azure control plane reports the resolver as healthy. Diagnose with NVA flow logs or `tcpdump` on the outbound endpoint's NIC.

> **Reference**: [Azure DNS Private Resolver Overview](https://learn.microsoft.com/en-us/azure/dns/dns-private-resolver-overview)

### 3.3 Management (`10.0.64.0/19`)

| Subnet | CIDR | Usable IPs | Purpose | Route Table | NSG |
|--------|------|------------|---------|-------------|-----|
| Subnet-AzureAutomation | `10.0.64.0/24` | 251 | Automation accounts | RT-Management | NSG-Management |
| Subnet-BackupVault | `10.0.65.0/24` | 251 | Recovery Services | RT-Management | NSG-Management |
| Subnet-UpdateManagement | `10.0.66.0/24` | 251 | Update Management | RT-Management | NSG-Management |

---

## 4. Application Landing Zones (Spokes) (`10.4.0.0/14`)

### 4.1 Spoke Allocation

| Environment | CIDR | Spoke Size | Max Spokes |
|-------------|------|------------|------------|
| Production | `10.4.0.0/15` | /22 (1,024 IPs) | 128 |
| Development | `10.6.0.0/16` | /24 (256 IPs) | 256 |
| Test/QA | `10.7.0.0/16` | /24 (256 IPs) | 256 |

#### 4.1.1 T-shirt sizing catalog (v5.0, CAF subscription-vending pattern)

[Plan for IP addressing](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/plan-for-ip-addressing) recommends T-shirt-sized address requests so application teams can self-describe their needs through subscription vending. The catalog maps directly onto the pools above:

| Size | Prefix | Addresses | Pool | Template | Allocation rule |
|------|--------|-----------|------|----------|-----------------|
| **Small** | `/24` | 256 | Dev `10.6.0.0/16` and Test `10.7.0.0/16` | Section 4.2.1 | Sequential from the bottom of the environment's /16 |
| **Medium** (default for Production) | `/22` | 1,024 | Prod `10.4.0.0/15` | Section 4.2 | Sequential **bottom-up** from `10.4.0.0/22` |
| **Large** | `/20` | 4,096 | Prod `10.4.0.0/15` (same pool) | Section 4.2 applied per-/22 quarter, or workload-defined (AKS CNI, AVS, big data) | **Top-down** from `10.5.240.0/20`, descending, each Large consumes a **/20-aligned run of four contiguous /22 slots** |

> **Why two-pointer allocation works**: every /20 boundary inside `10.4.0.0/15` coincides with a multiple of four /22 slots (4 × 1,024 = 4,096), so Medium spokes growing bottom-up and Large spokes growing top-down never fragment each other; the pools meet in the middle. Capacity trade-off is linear: each Large displaces exactly 4 Mediums (pure-Medium max = 128; pure-Large max = 32). First Large = `10.5.240.0/20`, second = `10.5.224.0/20`, and so on, alignment verified computationally.

> **Reserved-IP services**: when a workload declares AKS with Azure CNI (or anything else with per-node/per-pod IP reservation), size the request against the service's documented consumption *before* choosing the T-shirt, an AKS production cluster is a **Large** by default, never a Medium "to be enlarged later".

### 4.2 Standard Spoke Template (`/22`)

| Subnet | CIDR Offset | Size | Purpose | Route Table | NSG |
|--------|-------------|------|---------|-------------|-----|
| Subnet-Web | +0 | /25 | Web tier | RT-Spoke-Workloads | NSG-Spoke-Web |
| Subnet-App | +128 | /25 | Application tier | RT-Spoke-Workloads | NSG-Spoke-App |
| Subnet-Data | +256 | /25 | Database tier | RT-Spoke-Workloads | NSG-Spoke-Data |
| Subnet-PrivateEndpoints | +384 | /26 | Private Endpoints | RT-Spoke-Workloads | NSG-Spoke-PE |
| Subnet-Reserved | +448 | /26 | Future use | RT-Spoke-Workloads | NSG-Spoke-Reserved |

> **Spoke /22 utilisation**: The five subnets above consume 512 of the 1,024 addresses in the /22. The upper /23 (offsets +512 through +1023) is **reserved for future expansion** (e.g., additional tiers, dedicated AKS node pools, Private Endpoint growth). Effective usable host count across the five subnets is **487** (512 − 5 subnets × 5 Azure-reserved addresses), not the 1,019 a single flat /22 subnet would give, see Section 16.

### 4.2.1 Dev/Test Spoke Template (`/24`): v4.9 addition

The /22 template **cannot** be applied to Dev (`10.6.0.0/16`) and Test (`10.7.0.0/16`) spokes: its five subnets alone span 512 addresses, double a /24. v4.7 left these spokes template-less. The standard /24 carve is:

| Subnet | CIDR Offset | Size | Purpose | Route Table | NSG |
|--------|-------------|------|---------|-------------|-----|
| Subnet-Workload | +0 | /26 | Combined web/app tier | RT-Spoke-Workloads | NSG-Spoke-App |
| Subnet-Data | +64 | /26 | Database tier | RT-Spoke-Workloads | NSG-Spoke-Data |
| Subnet-PrivateEndpoints | +128 | /27 | Private Endpoints | RT-Spoke-Workloads | NSG-Spoke-PE |
| Subnet-Reserved | +160 | /27 + /26 (`+192`) | Future use | - | - |

> Dev/Test collapses web+app into one tier (cost/scale realities of non-prod) while keeping the **same NSG and route-table objects** as production so promotion testing exercises identical security semantics. If a dev workload genuinely needs the full 3-tier layout, allocate it a production-pattern /22 from the reserved platform-growth space instead of overstuffing a /24.

### 4.3 Hub-Spoke VNet Peering Configuration

Every spoke must peer with the Hub using the exact flag combinations below. **Missing or mismatched flags are silent failures**: the peering object exists but traffic will not transit correctly. This is the single most common source of "deployment succeeded but nothing works" incidents.

#### 4.3.1 Hub → Spoke Peering (configured on the Hub VNet)

| Flag | Value | Reason |
|------|-------|--------|
| `AllowVirtualNetworkAccess` | `true` | Default. Permits VM-to-VM connectivity between hub and spoke. |
| `AllowForwardedTraffic` | `true` | Permits the **Hub** to accept traffic arriving from the spoke whose source IP is outside the spoke's address space (e.g., a future spoke-hosted NVA forwarding on behalf of others). Rarely exercised today, but kept `true` for symmetry and future-proofing. |
| `AllowGatewayTransit` | `true` | **Required**. Allows the Hub's VPN/ExpressRoute gateway to serve the spoke. |
| `UseRemoteGateways` | `false` | The Hub owns the gateway; must not point to any remote one. |

#### 4.3.2 Spoke → Hub Peering (configured on each spoke VNet)

| Flag | Value | Reason |
|------|-------|--------|
| `AllowVirtualNetworkAccess` | `true` | Default. Permits VM-to-VM connectivity between spoke and hub. |
| `AllowForwardedTraffic` | `true` | **Required**. Permits the **spoke** to accept packets forwarded by the Hub's NVAs whose source IP is outside the Hub's address space, i.e., the un-SNAT'd return/forward legs from on-prem and platform sources transiting the EW NVA. Without it, Azure silently drops these at the peering boundary. |
| `AllowGatewayTransit` | `false` | The spoke does not host a gateway. |
| `UseRemoteGateways` | `true` | **Required**. Spoke uses the Hub's gateway for on-prem connectivity via gateway transit. |

> **v4.9 fix, rationale cells corrected**: v4.7 had the two `AllowForwardedTraffic` explanations swapped. The semantics: each peering side's flag controls whether **that** VNet accepts forwarded (non-remote-sourced) traffic **from** the remote VNet. The spoke-side flag is therefore the operationally critical one in a hub-NVA design, it is what legalises un-SNAT'd NVA-forwarded traffic entering the spoke. Both values were already `true`, so v4.7 was functionally correct; only the documentation was inverted.

#### 4.3.3 Spoke → Spoke Peering

Direct spoke-to-spoke peering is **not permitted** in this design. All East-West traffic must transit the EW NVA via the Hub. Spokes reach each other through the Hub's `ILB-EW-Outbound` per `RT-Spoke-Workloads` (Section 7.1).

> **Validation**: the `AllowForwardedTraffic = true` flag on both sides of every peering is what makes NVA traversal legal between spokes. Without it, Azure silently drops the packets at the peering boundary.

> **Gateway-transit anti-pattern**: a spoke with its own local VPN/ER gateway **must not** set `UseRemoteGateways = true`. Configuring both is invalid, Azure rejects the peering.

> **v5.0 (CAF), peering operations at scale**: (a) whenever the **Hub VNet address space changes** (a fourth /19 prefix is added per Section 3.0), every existing spoke peering requires a **resync** before the new prefix is reachable, schedule it as part of the change, it is online but per-peering; (b) at hundreds of spokes, manage peering creation and the Section 4.3 flag set through **Azure Virtual Network Manager** connectivity configurations (hub-and-spoke topology type) instead of per-spoke IaC peering resources, AVNM enforces the flag combinations centrally and remediates drift.

### 4.4 IPAM & Subscription Vending Integration (v5.0, CAF)

Address allocation is an **API-driven step inside subscription vending**, not a spreadsheet ritual. Per CAF's IPAM guidance:

| Requirement | Implementation in this design |
|---|---|
| Centralized inventory & overlap prevention | Deploy **[Azure IPAM](https://azure.github.io/ipam)** (open-source, Azure-native, Entra ID auth, REST API) in the Management subscription. Seed it with the Section 2 regional /13 template; it auto-discovers actual VNet utilization tenant-wide. |
| Request sizing | Application teams request by **T-shirt size** (Section 4.1.1) through the vending pipeline; the pipeline maps S/M/L → pool → next slot per the Section 4.1.1 allocation rules. |
| IaC integration | The vending pipeline calls the IPAM **reservation API** before `terraform plan` (Terraform external/HTTP data source or Bicep deployment script) and injects the reserved CIDR into the spoke module, no human picks an address. The fact-check report's Section L gates then validate the result. |
| Structure | Organize IPAM blocks by **region → environment → workload archetype** mirroring Section 2/Section 4 exactly, so the inventory *is* this document's tables, live. |
| Decommissioning | Workload offboarding **releases the reservation** in the same pipeline run that destroys the spoke; freed /22 and /24 slots return to their pool's free list (the two-pointer Large/Medium scheme in Section 4.1.1 stays fragmentation-free because releases re-enter the correct end). |

---

## 5. Internal Load Balancer (ILB) VIPs

| ILB Name | VIP Address | Subnet | Backend Pool | Purpose |
|----------|-------------|--------|--------------|---------|
| ILB-NS-Outbound | `10.0.3.100` | Subnet-NS-Internal | NS NVA internal NICs | Outbound to Internet |
| ILB-EW-Outbound | `10.0.5.100` | Subnet-EW-Internal | EW NVA internal NICs | Traffic entering and exiting EW NVA |

> **Critical**: All ILBs must use **Standard SKU** with **HA Ports** enabled for symmetric flow handling.

> **v4.9 fix, ILB-NS-Inbound removed**: v4.7 still listed `ILB-NS-Inbound (10.0.2.100)` even though the only route referencing it was deleted in v4.6 (F5) and no NSG, flow, or checklist used it. More fundamentally, an **internal** (private-frontend) load balancer cannot terminate Internet-initiated ingress, Internet traffic never reaches a private frontend. Published inbound services instead enter via **(a)** public IPs on the NS NVA external NICs (vendor-managed failover), or **(b)** a **public Standard Load Balancer** in front of Subnet-NS-External with per-service rules (no HA Ports on public LBs, HA Ports are an internal-LB-only feature), or **(c)** **Azure Application Gateway (with WAF) deployed per-application inside the owning spoke landing zone**: **never as a shared service in the hub**, per the CAF [traditional-topology](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/traditional-azure-networking-topology) rule against shared L7 inbound NVAs in the central hub (the Online-spoke pattern, Section 1.2.2), with **Azure Front Door** in front for global/multi-region HTTP(S) entry. Reserve `10.0.2.100` (do not reassign) in case a future private inbound design emerges.

> **Architecture Simplification**: `ILB-EW-Outbound` (`10.0.5.100`) is the **single entry point** for all East-West inspection. All spoke, platform, and NS-internal traffic routes to this ILB. The previous Transit ILB and ILB-EW-Inbound have been consolidated into this single ILB. EW NVA external NICs (Subnet-EW-External) are retained for management plane and future expansion but carry no data plane traffic in this design.

---

## 6. NVA & Load Balancer Configuration

### 6.1 NVA Interface Design

Each NVA has **two data-plane NICs** (External + Internal) **plus a separate out-of-band Management NIC**: three arms in total. The "*not 3*" wording from earlier versions referred only to the removed legacy **Transit** *data-plane* NIC (its VIP was consolidated into `Subnet-EW-Internal`, Section 5); it never meant the management interface is omitted.

| NVA Role | NIC 1, **External** (data) | NIC 2, **Internal** (data) | NIC 3, **Management** (out-of-band) |
|----------|------------------|------------------|------------------|
| North-South NVA | `Subnet-NS-External` (`10.0.2.x`) | `Subnet-NS-Internal` (`10.0.3.x`) | `Subnet-NVA-Management` (`10.0.7.x`) |
| East-West NVA | `Subnet-EW-External` (`10.0.4.x`) | `Subnet-EW-Internal` (`10.0.5.x`) | `Subnet-NVA-Management` (`10.0.7.x`) |

#### 6.1.1 Why three NVA arms: the design concept (External · Internal · Management)

A stateful inline NVA is inserted as a **"sandwich"**: to force the Azure fabric to route *through* the appliance instead of around it, traffic must **arrive on one interface and leave by another**. A single-NIC appliance cannot be reliably inserted inline, Azure routes by destination against a subnet's effective routes and does **not** honour a guest-OS next hop pointing at another address in the *same* subnet (the same fabric rule behind the Section 19/F2 chain design). Two data-plane arms give that clean ingress/egress split; a third, isolated arm keeps the appliance manageable no matter what the data plane is doing.

| Arm | Subnet (NS / EW) | Trust side it faces | What it carries | Route table | NSG posture | Why it is its own arm |
|---|---|---|---|---|---|---|
| **External** | `Subnet-NS-External` / `Subnet-EW-External` | **Untrusted / edge**: Internet (NS) or reserved for management-plane & future use (EW; no data plane today, Section 5) | NS: Internet **ingress** (published via NVA public IPs or a public Standard LB) and **egress NAT**. EW: none in this design. | `RT-NS-External` / `RT-EW-External` | Permissive only *toward the edge it faces* (e.g. Internet 80/443 inbound on NS, Section 9.2) but still ends in `DenyAllInbound`. | Keeps the dirty, Internet-facing leg physically separate from the inspected leg, so you can front it with public IPs / a public LB without ever exposing the internal side. |
| **Internal** | `Subnet-NS-Internal` / `Subnet-EW-Internal` | **Trusted / VNet**: the hub-and-spoke side | Hosts the **ILB VIP `.100`** that every spoke/platform/gateway UDR targets; is the **SNAT source IP** that pins return traffic to the same instance (Section 6.5); on the EW side carries the **BGP on-prem return path** (Section 7.5). | `RT-NS-Internal` / `RT-EW-Internal` | Allows exactly the hub/spoke/platform sources that legitimately enter the inspector (Section 9.3/Section 9.5). | This is the interface the **entire landing zone routes *to***. Separating it from External prevents hairpin loops and gives the SNAT / return-path anchor a single stable home (`.100`). |
| **Management** | `Subnet-NVA-Management` (`10.0.7.0/24`) | **Admin / out-of-band**: never the data path | **No inspected data.** Admin SSH/HTTPS consoles, vendor licensing & update calls, config sync and HA heartbeat. | `RT-NVA-Mgmt` (Section 7.7) | `NSG-NVA-Mgmt`, inbound 22/443 **only** from jump servers + on-prem admin ranges; nothing from spokes. | (a) You can still reach the appliance to **fix it when data-plane routing is broken**; (b) least privilege, admin access is scoped to known sources, not the workload fabric; (c) a data-plane NSG/RT change can't accidentally **lock you out**; (d) clean audit separation of control traffic from inspected traffic. |

> **One-line mental model**: **External = the dirty/edge side · Internal = the clean/VNet side the landing zone routes *to* · Management = the out-of-band door you keep your own key to.** The same three-arm split repeats for every chained group (Section 19): each group's own Internal subnet hosts its VIP, while all groups share the one Management subnet (a static-NIC budget check keeps it inside the /24, Section 19.2/Section 24).

### 6.2 Health Probe Configuration

| Setting | Recommended Value |
|---------|-------------------|
| Protocol | TCP |
| Port | 443 or custom health port (e.g., 65500) |
| Interval | 5 seconds |
| Unhealthy threshold | 2 consecutive failures |

### 6.3 Symmetric Routing Requirements

- **HA Ports**: Enable on all ILB rules to ensure all protocols/ports use same NVA instance
- **Floating IP**: Enable for scenarios requiring original destination IP preservation
- **Session Persistence**: Use 5-tuple hash (default) for stateful inspection

### 6.4 NVA Floating IP Configuration

> **Critical**: When Floating IP (Direct Server Return) is enabled on the ILB, packets arrive at the NVA with the **destination IP set to the ILB VIP**, not the VM's NIC IP.

**Required NVA Configuration:**
1. Configure a loopback interface on each NVA with the ILB VIP addresses
2. For Linux NVAs: Add VIP to `lo` interface or use `ip addr add <VIP>/32 dev lo`
3. For Windows NVAs: Add VIP to loopback adapter via `netsh interface ipv4 add address "Loopback" <VIP> 255.255.255.255`
4. Ensure NVA firewall/routing accepts traffic destined to the VIP

**Loopback IPs to Configure on NVAs:**

| NVA Role | Loopback IPs Required |
|----------|----------------------|
| North-South NVA | `10.0.3.100` |
| East-West NVA | `10.0.5.100` |

> **v4.9 fix**: `10.0.2.100` dropped from the NS loopback list, `ILB-NS-Inbound` was removed in Section 5 (private ILBs cannot receive Internet ingress; the VIP was unreferenced after the v4.6 F5 route deletion).

### 6.5 East-West NVA SNAT Configuration

> **Critical**: Configure the East-West NVA to **SNAT (Source NAT)** all spoke-to-spoke traffic.

**Why SNAT is Required:**
- Ensures symmetric routing without requiring return routes on destination spokes
- Return traffic automatically routes back to the NVA (source IP is NVA's interface IP)
- Simplifies spoke routing tables and prevents asymmetric flow issues

**SNAT Configuration:**
- SNAT source IP: Use the NVA's internal interface IP (`10.0.5.x`)
- Apply SNAT to traffic leaving the NVA towards spoke destinations (`10.4.0.0/14`) **and towards PE-hosting subnets** (`10.0.8.0/24` hub PE, `10.0.35.0/24` Key Vault PE, spoke PE subnets), **v5.2 fix**: Private Endpoint *return* traffic bypasses UDRs, so an un-SNAT'd NVA→PE leg would be asymmetric and break; SNAT pins the return to the NVA. This resolves the former Section 6.5 (spokes-only) vs Section 11.3 (PE rules assume SNAT) contradiction.
- Preserve original source IP in NVA logs for audit purposes

**Azure Firewall SNAT Behavior (if used instead of third-party NVA):**
- By default, Azure Firewall does **NOT** SNAT traffic to RFC 1918 private ranges **or RFC 6598 (`100.64.0.0/10`)**: the default no-SNAT set covers both (keyword `IANAPrivateRanges`)
- To force SNAT for inter-spoke traffic, configure Private IP ranges to `255.255.255.255/32` (always SNAT)
- Application rules **always** SNAT regardless of configuration
- Network rules respect the SNAT private ranges setting
- **Policy-managed firewalls ignore the classic `PrivateRange` property**: configure SNAT ranges on the Firewall Policy, not the firewall resource

> **Reference**: [Azure Firewall SNAT private IP address ranges](https://learn.microsoft.com/en-us/azure/firewall/snat-private-range)

### 6.6 NVA Sizing

| Tier | VM Size | Typical Inspected Throughput | Use Case |
|------|---------|------------------------------|----------|
| Small | Standard_D4s_v5 | ~2 Gbps | Dev/Test |
| Medium | Standard_D8s_v5 | ~5 Gbps | Production (small) |
| Large | Standard_D16s_v5 | ~10 Gbps | Production (large) |

> **v4.9 clarification**: the throughput column reflects **vendor-published inspection throughput** (firewalling + logging enabled), not Azure NIC bandwidth. The Azure platform limits differ, e.g., `Standard_D4s_v5` provides up to **12.5 Gbps** network bandwidth per the [Dsv5 series documentation](https://learn.microsoft.com/en-us/azure/virtual-machines/sizes/general-purpose/dsv5-series). Deep-packet inspection, TLS interception, and IPS features reduce effective throughput far below the NIC ceiling; always size from the **vendor's** datasheet for the feature set in use, and validate with a load test before production cutover.

### 6.7 Flow Symmetry: Why the Un-SNAT'd Paths Work

The EW NVA SNATs **only** traffic toward spokes (`10.4.0.0/14`, Section 6.5). Two path families deliberately remain **un-SNAT'd**:

1. **Spoke → Platform/Shared Services** (e.g., spoke VM → DC at `10.0.33.x`): forward leg enters via `ILB-EW-Outbound`; return leg from the platform subnet is routed by `RT-Platform-Workloads` (`To-Spokes → 10.0.5.100`) back to the **same ILB**.
2. **On-prem ↔ Platform** : forward leg arrives via GatewaySubnet and `RT-GatewaySubnet` (`→ 10.0.5.100`); return leg is steered by `RT-Platform-Workloads` (`To-OnPremises → 10.0.5.100`) to the **same ILB**.

These work without SNAT because of a documented Standard Load Balancer property: per the [Azure Architecture Center HA-NVA guide](https://learn.microsoft.com/en-us/azure/architecture/networking/guide/network-virtual-appliance-high-availability), **when both directions of a flow traverse the same load balancer, the load balancer selects the same NVA instance for both directions**. Both legs hitting `ILB-EW-Outbound` (HA Ports) therefore land on the same NVA, and the stateful firewall sees a complete session.

> **Design invariant**: any new flow added to this architecture must either (a) be SNAT'd by the NVA, or (b) have **both** directions routed through `ILB-EW-Outbound`. A flow whose return leg bypasses the ILB (system route, different ILB, or direct peering) will be dropped by the NVA's state table. Validate with the Section 17 Phase 7 tests after any routing change.

> **v5.1 extension**: Section 6 above describes a **single NVA group per tier**: the default, reproduced exactly. For ordered **multi-group chains** see Section 19, **chained Azure Firewall** on the same tiers see Section 20, and **VMSS-based appliance groups** see Section 21. Each chain segment must independently satisfy the invariant above, both directions through the same group ILB, or SNAT at the group.

---

## 7. Route Tables (UDRs)

### 7.0 RT-GatewaySubnet (Applied to GatewaySubnet)

| Route Name | Address Prefix | Next Hop Type | Next Hop Address |
|------------|----------------|---------------|------------------|
| To-`<spoke-name>`, **one route per spoke, exact prefix** | `10.4.0.0/22`, `10.4.4.0/22`, `10.5.240.0/20`, `10.6.0.0/24`, … | Virtual Appliance | `10.0.5.100` (ILB-EW-Outbound) |
| To-SharedServices | `10.0.32.0/19` | Virtual Appliance | `10.0.5.100` (ILB-EW-Outbound) |
| To-Management | `10.0.64.0/19` | Virtual Appliance | `10.0.5.100` (ILB-EW-Outbound) |

**BGP Propagation**: Enabled (Required, disabling breaks the gateway)

> **v5.2 (F1), exact spoke prefixes are mandatory**: gateway transit gives the GatewaySubnet a peering system route for **each spoke VNet's address space** (/22, /20, /24 …). Azure picks routes by longest-prefix-match across all sources, so the former `To-Spokes 10.4.0.0/14` summary **never fired**: on-prem→spoke traffic went direct (uninspected), while the spoke's return UDR steered through the EW NVA, which dropped the one-sided flow. An equal-prefix UDR ties with the peering route and wins (User > BGP > System), restoring inspection and symmetry. The AzIP-Ranger vending flow appends/removes the route as spokes are allocated/decommissioned; budget UDRs (400/table default, 1,000 with AVNM, Section 15.4).

> **Critical**: This route table ensures on-premises traffic arriving via VPN/ExpressRoute is routed through the EW NVA for inspection before reaching spokes or platform services. A `0.0.0.0/0` route is **NOT permitted** on GatewaySubnet, only specific destination prefixes are allowed. BGP propagation **must** remain enabled.

### 7.1 RT-Spoke-Workloads (Applied to all spoke subnets)

| Route Name | Address Prefix | Next Hop Type | Next Hop Address |
|------------|----------------|---------------|------------------|
| To-Internet | `0.0.0.0/0` | Virtual Appliance | `10.0.3.100` (ILB-NS-Outbound) |
| To-Hub-Connectivity | `10.0.0.0/19` | Virtual Appliance | `10.0.5.100` (ILB-EW-Outbound) |
| To-Hub-SharedServices | `10.0.32.0/19` | Virtual Appliance | `10.0.5.100` (ILB-EW-Outbound) |
| To-Hub-Management | `10.0.64.0/19` | Virtual Appliance | `10.0.5.100` (ILB-EW-Outbound) |
| To-Hub-Plan (inspected black-hole) | `10.0.0.0/16` | Virtual Appliance | `10.0.5.100` (ILB-EW-Outbound) |
| To-OtherSpokes | `10.4.0.0/14` | Virtual Appliance | `10.0.5.100` (ILB-EW-Outbound) |
| To-OnPremises | `<on-prem-supernet>` | Virtual Appliance | `10.0.5.100` (ILB-EW-Outbound) |
| To-Bastion-Direct | `10.0.1.0/26` | Virtual Network | - |
| To-NVA-Internal-Direct, **one per NVA internal subnet** (EW + NS, incl. Section 19 chain segments) | `10.0.5.0/24`, `10.0.3.0/24`, (`10.0.9.0/24`, …) | Virtual Network | - |

**BGP Propagation**: Disabled

> **v5.2 (F1), why three /19s instead of the /16**: the spoke's peering system routes equal the hub VNet's **declared prefixes** (the three /19s since v5.0 C-1). A `/16` UDR is less specific and loses the LPM tie-break, every spoke→hub flow silently bypassed the EW NVA (a v5.0 regression: with a /16 hub VNet the prefixes matched and the UDR won). Equal-prefix /19 UDRs restore inspection; `To-Hub-Plan /16` is retained purely as the inspected black-hole for unassigned hub space (Section 3.0). `To-Bastion-Direct` keeps Bastion→VM session returns off the inspection path (Bastion traffic arrives via the VNet directly, a steered return would be one-sided and dropped). `To-OtherSpokes` may stay a summary: spokes never peer with each other, so no competing system route exists.

> **On-premises parameterisation**: Replace `<on-prem-supernet>` with your actual on-premises address space. The example value `192.168.0.0/16` in prior diagrams is illustrative only. If on-prem spans multiple non-contiguous ranges (e.g., `10.100.0.0/16` + `172.16.0.0/12`), add **one UDR per prefix**, or advertise a supernet from on-prem that covers all of them. Hard-coding a placeholder risks missed destinations because BGP propagation is disabled on this route table.

> **Critical Route**: `To-NVA-Internal-Direct` ensures SNAT return traffic from the NVA (`10.0.5.x`) bypasses the ILB and reaches the specific NVA instance directly. This prevents asymmetric routing in Active-Active scenarios where the ILB might hash return traffic to a different NVA.

### 7.2 RT-NS-External

| Route Name | Address Prefix | Next Hop Type | Next Hop Address |
|------------|----------------|---------------|------------------|
| To-`<spoke-name>`, one route per spoke, exact prefix (v5.2/F1) | `10.4.0.0/22`, `10.4.4.0/22`, … | Virtual Appliance | `10.0.3.100` (ILB-NS-Outbound) |
| To-SharedServices | `10.0.32.0/19` | Virtual Appliance | `10.0.3.100` (ILB-NS-Outbound) |
| To-Management | `10.0.64.0/19` | Virtual Appliance | `10.0.3.100` (ILB-NS-Outbound) |

**BGP Propagation**: Disabled

> **v4.6 fix**: BGP propagation flipped from Enabled → Disabled. The NS NVA external NIC faces Internet (via Public IPs) and does not originate or terminate on-premises traffic. Learning on-prem prefixes here has no functional benefit and risks undesired routing. On-prem traffic reaches spokes via the EW NVA per RT-GatewaySubnet (Section 7.0), never via NS.

> **v4.7 clarification, these routes are defensive, not a sandwich loop**: The `To-Spokes` and `To-SharedServices` routes on RT-NS-External are intentional **defense-in-depth** for the case where the NS NVA OS routing table incorrectly egresses an internal-destined packet out the external NIC. In that (misconfiguration) scenario, the UDR intercepts the stray packet at the Azure fabric layer and cascades it through `ILB-NS-Outbound → NS NVA internal NIC`, where `RT-NS-Internal`'s `To-Spokes → ILB-EW-Outbound` then forwards it to the EW NVA for inspection. This is a **cascade** (external → internal → EW), not a loop, the packet monotonically moves across tiers and never returns to its origin. **Do not remove these routes** without first confirming the NVA OS can never hairpin internal-destined traffic out the external NIC.

### 7.3 RT-NS-Internal

| Route Name | Address Prefix | Next Hop Type | Next Hop Address |
|------------|----------------|---------------|------------------|
| *(no routes, single-group tier)* | - | - | - |

**BGP Propagation**: Disabled (the empty route table is kept precisely to pin this flag)

> **v5.2 (F1), `To-Spokes` removed**: the NS NVA's emissions toward spokes are *deliveries and un-NAT'd returns* (DNAT'd inbound publishing, internet-egress replies). Steering them into the EW ILB created **one-sided flows at the EW NVA**: the matching forward legs never crossed it, so a stateful inspector drops them. (Pre-v5.2 this never bit in deployments only because the /14 summary lost to the peering routes and the route was inert, see F1.) NS→spoke legs now ride the peering system routes; symmetry comes from the spoke RT's `To-NVA-Internal-Direct` routes back to the NS NVA's SNAT NICs.
>
> **When the tier is chained (Section 19)**: this table instead carries exactly one route, `To-NextChainHop 0.0.0.0/0 → <next segment hop>`, and each later segment's own subnet RT continues the cascade (`RT-NS-Internal-i`); the **last** segment returns to the empty table above (egress via the external NICs).

> **v4.6 fix**: removed the `0.0.0.0/0 → ILB-NS-Inbound (10.0.2.100)` route. That route was a hairpin, it would have sent Internet-bound traffic from the NVA's internal NIC back to its own inbound ILB. The NVA OS routes Internet-bound replies out its external NIC, which uses system default routing; no UDR is needed on the internal side. If a future scenario requires the internal NIC to originate Internet traffic, reintroduce the route with a clear rationale.

### 7.4 RT-EW-External

| Route Name | Address Prefix | Next Hop Type | Next Hop Address |
|------------|----------------|---------------|------------------|
| To-Spokes | `10.4.0.0/14` | Virtual Network | - |
| To-SharedServices | `10.0.32.0/19` | Virtual Network | - |
| To-Internet | `0.0.0.0/0` | Virtual Appliance | `10.0.3.100` (ILB-NS-Outbound) |

**BGP Propagation**: Disabled

> **Critical Fix**: `To-Spokes` and `To-SharedServices` now use **Virtual Network** (system routes via VNet peering) instead of pointing to the ILB. This prevents the routing loop where traffic would bounce between EW-External and EW-Internal interfaces indefinitely.

### 7.5 RT-EW-Internal

| Route Name | Address Prefix | Next Hop Type | Next Hop Address |
|------------|----------------|---------------|------------------|
| To-Spokes | `10.4.0.0/14` | Virtual Network | - |
| To-Hub | `10.0.0.0/16` | Virtual Network | - |

**BGP Propagation**: Enabled

> **v4.6 fix**: BGP propagation flipped from Disabled → Enabled. The EW NVA's internal NIC legitimately participates in bidirectional on-premises ↔ Azure flows (e.g., un-SNAT'd return packets going back to on-prem after an on-prem-initiated session to a spoke, Flow 13.3). Without BGP propagation, on-prem prefixes learned from the Gateway are absent from this subnet's effective routes, and the NVA has no route back to on-premises. Propagation is safe here because the explicit UDRs for `To-Spokes` and `To-Hub` (Virtual Network next-hop) override any BGP-learned routes for those ranges via LPM.

> **Critical Fix (retained from v4.5)**: `To-Spokes` and `To-Hub` use **Virtual Network** (system routes) instead of pointing to the ILB. The NVA egresses traffic directly to spokes via VNet peering, not back through its own load balancer.

> **v5.2 (F2), role in chained tiers**: with ≥ 2 chained EW groups this table describes **group 1's client-facing subnet only** (returns/deliveries toward clients + the BGP on-prem return path). Group 1's *forward* leg leaves from `Subnet-EW-Forward` (`RT-EW-Forward`: per-spoke + platform prefixes → hop 2), and segments 2…n use `RT-EW-Internal-i`, see Section 19.5 for the full cascade tables.

### 7.6 RT-Platform-Workloads (All platform-initiated flows)

| Route Name | Address Prefix | Next Hop Type | Next Hop Address |
|------------|----------------|---------------|------------------|
| To-`<spoke-name>`, one route per spoke, exact prefix (v5.2/F1) | `10.4.0.0/22`, `10.4.4.0/22`, … | Virtual Appliance | `10.0.5.100` (ILB-EW-Outbound) |
| To-Internet | `0.0.0.0/0` | Virtual Appliance | `10.0.3.100` (ILB-NS-Outbound) |
| To-OnPremises | `<on-prem-supernet>` | Virtual Appliance | `10.0.5.100` (ILB-EW-Outbound) |

**BGP Propagation**: Disabled

> **Apply to**: Subnet-DomainControllers, Subnet-Monitoring, Subnet-KeyVault, Subnet-JumpServers  
> **Note**: DNS Resolver subnets (`Subnet-DNS-Inbound`, `Subnet-DNS-Outbound`) also use this route table.

> **On-premises parameterisation**: Same guidance as Section 7.1, replace `<on-prem-supernet>` with the actual on-prem address space, or add one UDR per prefix if non-contiguous.

> **Consolidation Note**: The previous `RT-SharedServices` has been merged into `RT-Platform-Workloads` as both had identical routes. All Shared Services subnets now use a single route table.

### 7.7 RT-NVA-Mgmt (Applied to Subnet-NVA-Management)

| Route Name | Address Prefix | Next Hop Type | Next Hop Address |
|------------|----------------|---------------|------------------|
| To-Internet | `0.0.0.0/0` | Virtual Appliance | `10.0.3.100` (ILB-NS-Outbound) |
| To-OnPremises | `<on-prem-supernet>` | Virtual Appliance | `10.0.5.100` (ILB-EW-Outbound) |
| To-`<spoke-name>`, one route per spoke, exact prefix (v5.2/F1) | `10.4.0.0/22`, `10.4.4.0/22`, … | Virtual Appliance | `10.0.5.100` (ILB-EW-Outbound) |

**BGP Propagation**: Disabled

> **v4.9 fix, table now defined**: `RT-NVA-Mgmt` was referenced in Section 3.1 since v4.5 but never specified, leaving deployment ambiguous. Routes mirror `RT-Platform-Workloads`: management-plane traffic (vendor licensing/updates → Internet via NS NVA, admin sessions from on-prem/jump hosts via EW NVA) is inspected like any platform flow. Intra-hub access from `Subnet-JumpServers` uses the direct system route (no SNAT, see Section 6.7). If the NVA vendor requires out-of-band management that must never depend on the data-plane NVAs, remove the `0.0.0.0/0` route and use a dedicated egress path instead, document the exception.

### 7.8 RT-Management (Applied to Management subnets)

| Route Name | Address Prefix | Next Hop Type | Next Hop Address |
|------------|----------------|---------------|------------------|
| To-Internet | `0.0.0.0/0` | Virtual Appliance | `10.0.3.100` (ILB-NS-Outbound) |
| To-OnPremises | `<on-prem-supernet>` | Virtual Appliance | `10.0.5.100` (ILB-EW-Outbound) |
| To-`<spoke-name>`, one route per spoke, exact prefix (v5.2/F1) | `10.4.0.0/22`, `10.4.4.0/22`, … | Virtual Appliance | `10.0.5.100` (ILB-EW-Outbound) |

**BGP Propagation**: Disabled

> **Apply to**: Subnet-AzureAutomation, Subnet-BackupVault, Subnet-UpdateManagement (Section 3.3).

> **v4.9 fix, table now defined**: `RT-Management` was referenced in Section 3.3 but never specified. Routes are identical to `RT-Platform-Workloads`; it is kept as a **separate** route table object so management-VNet route changes can be made without touching shared-services subnets (blast-radius isolation), at the cost of one more object to maintain. Merge into `RT-Platform-Workloads` if you prefer fewer objects.

---

## 8. BGP Propagation Guardrails

| Subnet / Route Table | BGP Propagation | Reason |
|----------------------|-----------------|--------|
| GatewaySubnet / RT-GatewaySubnet | Enabled (Required) | Must remain enabled for gateway functionality; disabling breaks the gateway. UDR used for spoke/platform routes only (no 0.0.0.0/0). |
| RouteServerSubnet | N/A (Azure-managed) | Cannot modify; no UDR or NSG supported |
| AzureBastionSubnet | N/A | UDR not supported on this subnet |
| RT-NS-External | Disabled | **v4.6 change**: NS NVA external NICs face Internet via Public IPs; do not originate or terminate on-prem traffic. |
| RT-NS-Internal | Disabled | v5.2: table is empty (or carries only the chain-cascade 0/0), kept to pin BGP off; NS NVA does not participate in on-prem flows. |
| RT-NS-Internal-i / RT-FW-Internal-i (chain segments, Section 19.5) | Disabled (last EW/single segment: Enabled) | Mid segments use explicit cascade routes only; the LAST East-West/single segment needs gateway routes for on-prem deliveries. |
| RT-EW-Forward / RT-FW-Forward (Section 19.5) | Disabled | Forward-steering only, explicit cascade routes. |
| RT-AzureFirewallSubnet (when chained mid-slot, Section 20) | Disabled | Explicit cascade routes to the next chain hop. |
| RT-EW-External | Disabled | Management/future expansion only; no data-plane traffic in current design. |
| RT-EW-Internal | Enabled | **v4.6 change**: EW NVA internal NICs participate in bidirectional on-prem flows; BGP-learned routes provide return path to on-premises. Explicit UDRs for `To-Spokes` and `To-Hub` override via LPM. |
| RT-Spoke-Workloads | Disabled | Force all traffic through NVA via explicit UDRs. |
| RT-Platform-Workloads | Disabled | Force all traffic through NVA (consolidates former RT-SharedServices) |
| RT-NVA-Mgmt | Disabled | Management plane follows the same inspected paths as platform workloads (Section 7.7). |
| RT-Management | Disabled | Identical routes to RT-Platform-Workloads; separate object for blast-radius isolation (Section 7.8). |

> **Reference**: [VPN Gateway - BGP route propagation must be enabled](https://learn.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-about-vpn-gateway-settings#gateway-subnet)

---

## 9. Network Security Groups (NSGs)

### 9.1 NSG-Bastion (Required for AzureBastionSubnet)

> **Critical**: Azure Bastion requires these exact NSG rules. Missing or incorrect rules will cause deployment failure or block connectivity. These rules are verified against Microsoft documentation.

#### Inbound Rules

| Priority | Name | Source | Source Port | Destination | Dest Port | Protocol | Action |
|----------|------|--------|-------------|-------------|-----------|----------|--------|
| 120 | AllowHttpsInbound | Internet | * | * | 443 | TCP | Allow |
| 130 | AllowGatewayManagerInbound | GatewayManager | * | * | 443 | TCP | Allow |
| 140 | AllowAzureLoadBalancerInbound | AzureLoadBalancer | * | * | 443 | TCP | Allow |
| 150 | AllowBastionHostCommunication | VirtualNetwork | * | VirtualNetwork | 8080,5701 | **Any** | Allow |
| 4096 | DenyAllInbound | Any | * | Any | * | Any | Deny |

#### Outbound Rules

| Priority | Name | Source | Source Port | Destination | Dest Port | Protocol | Action |
|----------|------|--------|-------------|-------------|-----------|----------|--------|
| 100 | AllowSshRdpOutbound | * | * | VirtualNetwork | 22,3389 | **Any** | Allow |
| 110 | AllowAzureCloudOutbound | * | * | AzureCloud | 443 | TCP | Allow |
| 120 | AllowBastionCommunication | VirtualNetwork | * | VirtualNetwork | 8080,5701 | **Any** | Allow |
| 130 | AllowHttpOutbound | * | * | Internet | 80 | **Any** | Allow |
| 4096 | DenyAllOutbound | Any | * | Any | * | Any | Deny |

> **Reference**: [Configure NSG rules for Azure Bastion](https://learn.microsoft.com/en-us/azure/bastion/bastion-nsg) (re-verified 2026-06-11)

**Validation Notes:**
- **v4.9, documented conflict in the MS reference and how it was resolved**: the current `bastion-nsg` page contains a normative summary table ("The following table summarizes all required NSG rules") that specifies protocol **`*` (Any)** for exactly four rules, `AllowBastionHostCommunication`, `AllowSshRdpOutbound`, `AllowBastionCommunication`, `AllowHttpOutbound`, while the PowerShell sample on the *same page* still uses `Tcp` for all 8. Per our tiebreaker policy (normative requirements statement over how-to sample artifact), this design follows the **summary table**: 4 rules `Any`, 4 rules `Tcp`. Note this means the v4.5 "Any" values were defensible and the v4.6 "all-Tcp" revert was over-corrected against the PowerShell sample. Restricting these 4 rules to TCP-only is functionally narrower than Microsoft's stated requirement (e.g., it would block any UDP transport on the 22/3389 egress path), do not tighten them without lab validation against your Bastion SKU.
- Port 8080 and 5701 are required for Bastion host-to-host communication (data plane)
- Port 443 inbound from GatewayManager is required for control plane
- Port 443 inbound from AzureLoadBalancer is required for health probes
- Port 80 outbound to Internet is required for session validation, **Bastion Shareable Link**, and certificate validation (per current doc, no SKU qualifier; applies whenever an NSG is attached)
- Custom ports (if using Standard/Premium SKU) require the outbound 22/3389 rule to target the **VirtualNetwork** tag rather than specific subnets
- **Target VM subnets need their own rule**: per the same doc, every subnet that hosts Bastion-managed VMs must allow inbound 22/3389 (or custom ports) **from `AzureBastionSubnet` (`10.0.1.0/26`)**. Because the spoke/shared-services NSGs in this design end with a custom `DenyAllInbound` at 4096, the default `AllowVnetInBound` never fires, the explicit rule is mandatory (see Sections 9.6-9.9, rule 140).

### 9.2 NSG-NS-External

| Priority | Name | Direction | Source | Destination | Port | Protocol | Action |
|----------|------|-----------|--------|-------------|------|----------|--------|
| 100 | AllowHTTPS-Inbound | Inbound | Internet | Subnet-NS-External | 443 | TCP | Allow |
| 110 | AllowHTTP-Inbound | Inbound | Internet | Subnet-NS-External | 80 | TCP | Allow |
| 150 | AllowAzureLoadBalancer | Inbound | AzureLoadBalancer | Any | Any | Any | Allow |
| 4096 | DenyAllInbound | Inbound | Any | Any | Any | Any | Deny |

> **v4.6 fix**: Removed the `AllowVPN-Inbound` rule (source `192.168.0.0/16`). Per the traffic flow in Section 13.3, on-premises traffic arrives at the GatewaySubnet and is routed via `RT-GatewaySubnet` directly to `ILB-EW-Outbound`, it never reaches `Subnet-NS-External`. The rule was dead weight and created a misleading impression that on-prem traffic could enter via this path.

### 9.3 NSG-NS-Internal

| Priority | Name | Direction | Source | Destination | Port | Protocol | Action |
|----------|------|-----------|--------|-------------|------|----------|--------|
| 100 | AllowFromSpokes | Inbound | `10.4.0.0/14` | NS internal subnet(s) | Any | Any | Allow |
| 110 | AllowFromSharedServices | Inbound | `10.0.32.0/19` | NS internal subnet(s) | Any | Any | Allow |
| 115 | AllowFromChainSegments *(chained tiers only, v5.2/F4)* | Inbound | all NS internal subnets (`10.0.3.0/24`, `10.0.9.0/24`, …) | NS internal subnet(s) | Any | Any | Allow |
| 120 | AllowFromEW | Inbound | `10.0.4.0/23` (+ EW chain/forward subnets when chained) | NS internal subnet(s) | Any | Any | Allow |
| 150 | AllowAzureLoadBalancer | Inbound | AzureLoadBalancer | Any | Any | Any | Allow |
| 4096 | DenyAllInbound | Inbound | Any | Any | Any | Any | Deny |

> **v5.2 (F4)**: the NSG applies to **every** NS internal subnet (base + Section 19 chain segments). `AllowFromChainSegments` legalises the fabric-routed hop-to-hop forward legs (each hop is a NEW inbound flow at the next segment; returns ride NSG flow state and need no rule). Without it the custom `DenyAllInbound 4096` silently killed chained traffic, the EW tier only escaped via its broad `AllowFromPlatform` rule.

### 9.4 NSG-EW-External

| Priority | Name | Direction | Source | Destination | Port | Protocol | Action |
|----------|------|-----------|--------|-------------|------|----------|--------|
| 100 | AllowFromSpokes | Inbound | `10.4.0.0/14` | Subnet-EW-External | Any | Any | Allow |
| 110 | AllowFromSharedServices | Inbound | `10.0.32.0/19` | Subnet-EW-External | Any | Any | Allow |
| 120 | AllowFromNS | Inbound | `10.0.2.0/23` | Subnet-EW-External | Any | Any | Allow |
| 130 | AllowFromPlatform | Inbound | `10.0.0.0/16` | Subnet-EW-External | Any | Any | Allow |
| 150 | AllowAzureLoadBalancer | Inbound | AzureLoadBalancer | Any | Any | Any | Allow |
| 4096 | DenyAllInbound | Inbound | Any | Any | Any | Any | Deny |

### 9.5 NSG-EW-Internal

Applies to **all** East-West internal subnets: `Subnet-EW-Internal` (+ `Subnet-EW-Internal-i` chain segments and `Subnet-EW-Forward` when chained, Section 19).

| Priority | Name | Direction | Source | Destination | Port | Protocol | Action |
|----------|------|-----------|--------|-------------|------|----------|--------|
| 100 | AllowFromEWExternal | Inbound | Subnet-EW-External | EW internal subnet(s) | Any | Any | Allow |
| 110 | AllowFromSpokes | Inbound | `10.4.0.0/14` | EW internal subnet(s) | Any | Any | Allow |
| 115 | AllowFromChainSegments *(chained tiers only, v5.2)* | Inbound | all EW internal + forward subnets | EW internal subnet(s) | Any | Any | Allow |
| 120 | AllowFromSharedServices | Inbound | `10.0.32.0/19` | EW internal subnet(s) | Any | Any | Allow |
| 125 | AllowFromAzureFirewall *(when chained into E-W, Section 20)* | Inbound | `10.0.0.128/26` | EW internal subnet(s) | Any | Any | Allow |
| 130 | AllowFromPlatform | Inbound | `10.0.0.0/16` | EW internal subnet(s) | Any | Any | Allow |
| 150 | AllowAzureLoadBalancer | Inbound | AzureLoadBalancer | Any | Any | Any | Allow |
| 4096 | DenyAllInbound | Inbound | Any | Any | Any | Any | Deny |

> **Note**: NSG-EW-Internal allows traffic from spokes and platform because `ILB-EW-Outbound` (`10.0.5.100`) is the entry point for all East-West inspection. Rule 115 is technically shadowed by rule 130 here, it is kept narrow and explicit for auditability of the chain legs.

### 9.6 NSG-SharedServices

#### Inbound Rules

| Priority | Name | Direction | Source | Destination | Port | Protocol | Action |
|----------|------|-----------|--------|-------------|------|----------|--------|
| 100 | AllowAD-TCP | Inbound | `10.0.0.0/12`, `<on-prem-supernet>` | Subnet-DomainControllers | 53,88,135,389,445,464,636,3268,3269,49152-65535 | TCP | Allow |
| 105 | AllowAD-UDP | Inbound | `10.0.0.0/12`, `<on-prem-supernet>` | Subnet-DomainControllers | 53,88,123,389,464 | UDP | Allow |
| 110 | AllowMonitoring | Inbound | `10.0.0.0/12` | Subnet-Monitoring | 443 | TCP | Allow |
| 115 | AllowKeyVaultPE *(v5.2/F5)* | Inbound | EW post-SNAT range (last chain segment, e.g. `10.0.5.0/24`), `10.0.32.0/19`, `10.0.64.0/19` | Subnet-KeyVault (`10.0.35.0/24`) | 443 | TCP | Allow |
| 140 | AllowBastionInbound | Inbound | `10.0.1.0/26` | Any | 22,3389 | TCP | Allow |
| 150 | AllowAzureLoadBalancer | Inbound | AzureLoadBalancer | Any | Any | Any | Allow |
| 4096 | DenyAllInbound | Inbound | Any | Any | Any | Any | Deny |

> **v4.9 fix, AD port set and sources**: the previous rule (`389,636,88,445` TCP only) would have **broken Active Directory**: Kerberos (88) and DNS (53) also require UDP, domain join/replication require RPC Endpoint Mapper (135/TCP) plus the dynamic RPC range (49152–65535/TCP), Kerberos password change uses 464 (TCP+UDP), Global Catalog uses 3268/3269, and W32Time uses 123/UDP. Source also now includes `<on-prem-supernet>`, without it, on-prem DC replication and on-prem client logons against Azure DCs were denied by rule 4096 (on-prem is not inside `10.0.0.0/12`). Port list per [How to configure a firewall for Active Directory domains and trusts](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/config-firewall-for-ad-domains-and-trusts). Restrict the dynamic RPC range further only if your DCs pin a static RPC port.

> **v4.9 fix, Bastion ingress (rule 140)**: required by the Bastion NSG doc on every target-VM subnet; the custom `DenyAllInbound` (4096) otherwise blocks Bastion sessions to DCs/monitoring/jump VMs because the default `AllowVnetInBound` (65000) is never reached.

> **v5.2 fix, Key Vault PE reachability (rule 115, F5)**: `Subnet-KeyVault` hosts private endpoints, and with `privateEndpointNetworkPolicies = Enabled` this NSG is enforced on them, yet no prior rule allowed 443 to `10.0.35.0/24`, so **every** Key Vault PE was unreachable. Spoke clients arrive post-SNAT from the East-West inspector (Section 6.5 v5.2 scope), hub/management clients intra-VNet, and on-prem arrives post-SNAT via the EW path (`RT-GatewaySubnet` routes Shared /19 through it).

#### Outbound Rules

| Priority | Name | Direction | Source | Destination | Port | Protocol | Action |
|----------|------|-----------|--------|-------------|------|----------|--------|
| 200 | AllowOutboundToSpokes | Outbound | Any | `10.4.0.0/14` | Any | Any | Allow |
| 210 | AllowOutboundToInternet | Outbound | Any | Internet | 443 | TCP | Allow |

> **Note**: DNS rules removed from this NSG. DNS Resolver subnets do not support NSGs. DNS traffic is allowed by Azure platform for the resolver service.

### 9.7 NSG-Spoke-Web (Example)

| Priority | Name | Direction | Source | Destination | Port | Protocol | Action |
|----------|------|-----------|--------|-------------|------|----------|--------|
| 100 | AllowHTTPS | Inbound | Any | ASG-WebServers | 443 | TCP | Allow |
| 110 | AllowHTTP | Inbound | Any | ASG-WebServers | 80 | TCP | Allow |
| 120 | AllowFromAppTier | Inbound | ASG-AppServers | ASG-WebServers | 8080 | TCP | Allow |
| 140 | AllowBastionInbound | Inbound | `10.0.1.0/26` | Any | 22,3389 | TCP | Allow |
| 150 | AllowAzureLoadBalancer | Inbound | AzureLoadBalancer | Any | Any | Any | Allow |
| 4096 | DenyAllInbound | Inbound | Any | Any | Any | Any | Deny |

### 9.8 NSG-Spoke-App (Example)

| Priority | Name | Direction | Source | Destination | Port | Protocol | Action |
|----------|------|-----------|--------|-------------|------|----------|--------|
| 100 | AllowFromWebTier | Inbound | ASG-WebServers | ASG-AppServers | 8080,8443 | TCP | Allow |
| 140 | AllowBastionInbound | Inbound | `10.0.1.0/26` | Any | 22,3389 | TCP | Allow |
| 150 | AllowAzureLoadBalancer | Inbound | AzureLoadBalancer | Any | Any | Any | Allow |
| 4096 | DenyAllInbound | Inbound | Any | Any | Any | Any | Deny |

> **v5.2 (F6)**: the former rule 110 (`AllowFromDataTier, ASG-DataServers → ASG-AppServers : 1433`) was removed. NSGs are **stateful**: returns of app→data SQL sessions need no inbound rule, and no documented flow has the data tier *initiating* 1433 connections to the app tier. Dead allow rules widen the audit surface.

### 9.9 NSG-Spoke-Data (Example)

| Priority | Name | Direction | Source | Destination | Port | Protocol | Action |
|----------|------|-----------|--------|-------------|------|----------|--------|
| 100 | AllowSQL | Inbound | ASG-AppServers | ASG-DataServers | 1433 | TCP | Allow |
| 110 | AllowBackup | Inbound | `10.0.65.0/24` | ASG-DataServers | 443 | TCP | Allow |
| 140 | AllowBastionInbound | Inbound | `10.0.1.0/26` | Any | 22,3389 | TCP | Allow |
| 150 | AllowAzureLoadBalancer | Inbound | AzureLoadBalancer | Any | Any | Any | Allow |
| 4096 | DenyAllInbound | Inbound | Any | Any | Any | Any | Deny |

> **v4.9 fix, Bastion ingress (rule 140 in Sections 9.7-9.9)**: the [Bastion NSG documentation](https://learn.microsoft.com/en-us/azure/bastion/bastion-nsg) requires every target-VM subnet to permit inbound 22/3389 from `AzureBastionSubnet` (`10.0.1.0/26`). With the custom `DenyAllInbound` at 4096, the platform default `AllowVnetInBound` (65000) is never evaluated, so v4.7 silently blocked all Bastion sessions into spokes. Scope the destination to the relevant ASGs if you want tier-level precision.

---

## 10. Application Security Groups (ASGs)

### 10.1 Recommended ASG Structure

| ASG Name | Purpose | Example Members |
|----------|---------|-----------------|
| ASG-WebServers | Web tier VMs | IIS, Nginx, Apache servers |
| ASG-AppServers | Application tier VMs | API servers, middleware |
| ASG-DataServers | Database tier VMs | SQL Server, PostgreSQL |
| ASG-JumpServers | Administrative access | Bastion hosts, jump boxes |
| ASG-DomainControllers | AD infrastructure | Domain controllers |

### 10.2 ASG Benefits

- **Dynamic membership**: VMs automatically inherit rules when added to ASG
- **Simplified rules**: Reference ASG instead of IP addresses
- **Reduced rule count**: Single rule covers multiple VMs
- **Self-referencing**: Allow intra-tier communication easily

### 10.3 ASG Constraints

- ASGs must be in the same region as the NIC
- Cannot mix ASGs from different VNets in a single rule
- Maximum 3,000 ASGs per subscription

---

## 11. Private Endpoint Subnet Design

### 11.1 Hub Private Endpoint Subnet (`10.0.8.0/24`)

| Service | Example Endpoints |
|---------|-------------------|
| Key Vault | `kv-hub-001.privatelink.vaultcore.azure.net` |
| Storage | `sthub001.privatelink.blob.core.windows.net` |
| SQL | `sql-hub-001.privatelink.database.windows.net` |

### 11.2 Spoke Private Endpoint Subnet (per spoke)

- Allocate `/26` minimum per spoke for Private Endpoints
- Use dedicated NSG (`NSG-Spoke-PE`) with restrictive rules
- Set `privateEndpointNetworkPolicies` = **Enabled** on subnet to enforce NSG rules on Private Endpoint traffic

> **Important**: To apply NSG rules to Private Endpoint traffic, you must set `privateEndpointNetworkPolicies` to **Enabled**. If set to **Disabled**, NSG rules will **not** be enforced on Private Endpoint traffic.

### 11.3 Private Endpoint NSG Rules

| Priority | Name | Direction | Source | Destination | Port | Protocol | Action |
|----------|------|-----------|--------|-------------|------|----------|--------|
| 90 | AllowFromOwnSpoke *(spoke instantiations only, v5.2/F3)* | Inbound | `<own spoke VNet CIDR>` | Subnet-PE | 443 | TCP | Allow |
| 100 | AllowFromEW-SNAT | Inbound | EW post-SNAT range, the **last** chain segment's internal subnet (`10.0.5.0/24` single-group) | Subnet-PE | 443 | TCP | Allow |
| 110 | AllowFromSharedServices | Inbound | `10.0.32.0/19` | Subnet-PE | 443 | TCP | Allow |
| 120 | AllowFromOnPrem *(hub PE subnet only)* | Inbound | `<on-prem-supernet>` | Subnet-PE | 443 | TCP | Allow |
| 4096 | DenyAllInbound | Inbound | Any | Any | Any | Any | Deny |

> **v5.2 fix, own-spoke access (rule 90, F3)**: intra-spoke traffic to the spoke's own private endpoints rides the VNet system route (the spoke's own prefix is always more specific than any UDR), arrives **un-SNAT'd** with a spoke-local source, and matched no allow rule, every spoke's PEs were unreachable from their primary consumers. Each per-spoke NSG instantiation substitutes its own VNet CIDR; the **hub** PE subnet omits rule 90. Extend ports beyond 443 per service (e.g., 1433 for SQL private endpoints).

> **v4.6 fix, post-SNAT source**: Rule 100 now matches `10.0.5.0/24` (EW NVA internal NIC range) rather than the pre-SNAT workload range `10.4.0.0/14`. Azure NSGs evaluate the **post-SNAT source IP** at the destination NIC. Because the EW NVA SNATs spoke→PE traffic to its internal NIC IP (`10.0.5.x` per Section 6.5), a rule matching `10.4.0.0/14` would never fire for that path, the default `AllowVnetInBound` (priority 65000, source `VirtualNetwork`) would silently cover it, defeating the tight scoping this rule was meant to provide.

> **Shared Services path**: Rule 110 (source `10.0.32.0/19`) still applies unchanged because intra-hub traffic (Shared Services → Hub PE) uses system routes within the Hub VNet and is **not** SNAT'd.

> **v4.9 fix, on-prem path (rule 120)**: Section 11.5.3 promises on-prem clients can reach hub Private Endpoints, but v4.7's rule set ended at the SNAT'd-EW and Shared-Services sources, so rule 4096 denied every on-prem source IP. Rule 120 restores the path. Note the **data path is intentionally direct (uninspected)**: `RT-GatewaySubnet` carries no route for `10.0.8.0/24`, so GatewaySubnet → Hub PE follows the intra-VNet system route, and PE **return** traffic ignores UDRs anyway (return flows from a Private Endpoint bypass route tables unless `RouteTableEnabled`/`Enabled` policies plus a specific UDR pattern are engineered). Do **not** try to force this leg through the EW NVA without also extending the NVA SNAT scope to on-prem prefixes, asymmetry would break the flow. Inspect on-prem→PE traffic on-premises if policy requires it.

> **Direct Internet-initiated PE traffic**: Not permitted in this design, Private Endpoints are only reachable from within the VNet fabric or from on-prem via the Gateway.

### 11.4 DNS Configuration

- Use Azure Private DNS Zones for every Private Endpoint service in use
- Link every zone to the **Hub VNet** (where the DNS Private Resolver lives)
- Spokes do **not** link to Private DNS zones directly; they resolve through the Private Resolver's inbound endpoint (`10.0.32.4`) for simplicity and centralised control
- For on-premises resolution of Private Endpoints, configure on-prem DNS conditional forwarders to point to the inbound endpoint (`10.0.32.4`) for each `privatelink.*` zone
- The DNS forwarding ruleset on the outbound endpoint (`10.0.32.20`) forwards queries for on-prem domains out to on-prem DNS servers

> **Important**: `privateEndpointNetworkPolicies` on the PE subnet must be set to `Enabled` (applies both NSG and UDR) or to the more granular `NetworkSecurityGroupEnabled` (NSG only). Possible values per ARM/portal are `Disabled`, `NetworkSecurityGroupEnabled`, `RouteTableEnabled`, or `Enabled`. This design uses `Enabled` because both NSG (Section 11.3) and UDR (`RT-Spoke-Workloads`) enforcement are desired on PE traffic.

### 11.5 Private DNS Zone Linkage

Every Private Endpoint **must** have its corresponding `privatelink.*` zone linked to a VNet where the client can resolve it, otherwise the PE silently resolves to the service's **public** IP, defeating the private-link model.

#### 11.5.1 Required Zones by Service

| Service | Required `privatelink.*` Zone | Notes |
|---|---|---|
| Key Vault | `privatelink.vaultcore.azure.net` | - |
| Storage, blob | `privatelink.blob.core.windows.net` | One zone per sub-resource type if used |
| Storage, file | `privatelink.file.core.windows.net` | |
| Storage, queue | `privatelink.queue.core.windows.net` | |
| Storage, table | `privatelink.table.core.windows.net` | |
| Storage, DFS (Data Lake Gen2) | `privatelink.dfs.core.windows.net` | |
| Azure SQL Database / Managed Instance | `privatelink.database.windows.net` | |
| Cosmos DB (SQL API) | `privatelink.documents.azure.com` | Other APIs have their own zones |
| Azure Monitor / Log Analytics | `privatelink.monitor.azure.com`, `privatelink.oms.opinsights.azure.com`, `privatelink.ods.opinsights.azure.com`, `privatelink.agentsvc.azure-automation.net`, `privatelink.blob.core.windows.net` | Monitor requires the full AMPLS zone set |
| AKS private cluster | `privatelink.<region>.azmk8s.io` | Region-specific |
| App Service / Function Apps | `privatelink.azurewebsites.net`, `scm.privatelink.azurewebsites.net` | Both zones required |
| Azure Container Registry | `privatelink.azurecr.io` | |

> **Always check**: [Azure services DNS zone configuration](https://learn.microsoft.com/en-us/azure/private-link/private-endpoint-dns) for the full, current list of zones per service. New services ship zones periodically.

#### 11.5.2 VNet Link Topology (This Design)

| Zone | Hub VNet linked? | Spoke VNets linked? | On-prem resolution |
|---|---|---|---|
| All `privatelink.*` zones | **Yes** | No, spokes resolve via `10.0.32.4` | on-prem conditional forwarder → `10.0.32.4` |

**Rationale**: centralising every zone on the Hub VNet means (a) no per-spoke zone-link sprawl, (b) new PE zones are onboarded in one place, (c) on-prem and Azure share the same resolution path through the inbound endpoint. Spoke VNets use `10.0.32.4` as their configured DNS server.

#### 11.5.3 Required On-Premises Configuration

For every `privatelink.*` zone in Section 11.5.1, on-prem DNS servers must have a conditional forwarder:

| Zone | Forward to |
|---|---|
| `privatelink.vaultcore.azure.net` | `10.0.32.4` |
| `privatelink.blob.core.windows.net` | `10.0.32.4` |
| `privatelink.database.windows.net` | `10.0.32.4` |
| *(every other zone in use)* | `10.0.32.4` |

> **Reference**: [Private Endpoint DNS integration overview](https://learn.microsoft.com/en-us/azure/private-link/private-endpoint-dns) and [DNS Private Resolver hybrid resolution](https://learn.microsoft.com/en-us/azure/dns/private-resolver-hybrid-dns).

> **Anti-pattern**: Linking `privatelink.*` zones to the on-prem DNS system directly instead of forwarding to the inbound endpoint. This duplicates records and creates split-brain resolution risk.

---

## 12. Platform Subnet Hardening

### 12.1 GatewaySubnet

| Constraint | Requirement | Reference |
|------------|-------------|-----------|
| NSG | Not supported – cannot associate NSG | [ExpressRoute Gateway](https://learn.microsoft.com/en-us/azure/expressroute/expressroute-about-virtual-network-gateways#gateway-subnet) |
| UDR with 0.0.0.0/0 | Not supported – blocks gateway creation | [VPN Gateway Settings](https://learn.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-about-vpn-gateway-settings#gateway-subnet) |
| BGP Propagation | Must remain enabled – disabling breaks gateway | Same reference |
| Minimum Size | /27 (recommended /26 for coexistence) | [ExpressRoute Gateway](https://learn.microsoft.com/en-us/azure/expressroute/expressroute-about-virtual-network-gateways#gateway-subnet-size) |

### 12.2 RouteServerSubnet

| Constraint | Requirement | Reference |
|------------|-------------|-----------|
| NSG | Not supported – cannot associate NSG | [Route Server FAQ](https://learn.microsoft.com/en-us/azure/route-server/route-server-faq#limitations) |
| UDR | Not supported | Same reference |
| Minimum Size | /26 | [Route Server Quickstart](https://learn.microsoft.com/en-us/azure/route-server/quickstart-create-route-server-cli) |
| Naming | Must be named exactly `RouteServerSubnet` | Same reference |

**Operational guardrails (v4.9, verified against live docs), apply if/when Route Server is deployed:**

| Guardrail | Detail | Reference |
|---|---|---|
| NVA ASN | Must differ from **65515** (Route Server's fixed ASN) and avoid all Azure-reserved ASNs (private: 65515, 65517–65520; public: 8074, 8075, 12076) and IANA-reserved ASNs (23456, 64496–64511, 65535–65551). Only **16-bit ASNs** are supported. | [Route Server FAQ, Routing](https://learn.microsoft.com/en-us/azure/route-server/route-server-faq) |
| Peer scale | Max **16 BGP peers** per Route Server; max **4,000 routes per peer**: exceeding the route limit tears down the BGP session. | [Route Server FAQ, Limitations](https://learn.microsoft.com/en-us/azure/route-server/route-server-faq#limitations) |
| Dual sessions | Each NVA must establish **two identical BGP sessions** (same ASN, AS-path, route set) to both Route Server peer IPs, with **eBGP multi-hop enabled** (NVA and Route Server sit in different subnets). | [Troubleshoot Route Server](https://learn.microsoft.com/en-us/azure/route-server/troubleshoot-route-server) |
| Control plane is not data plane | Route Server **never forwards data traffic**: it only exchanges routes. Do **not** attempt to steer the Route Server ↔ NVA BGP/TCP-179 control plane through the EW/NS NVA data path: the RouteServerSubnet accepts no UDR, and Route Server needs its public-IP management plane reachable. Peering rides intra-VNet system routes. | [Route Server FAQ](https://learn.microsoft.com/en-us/azure/route-server/route-server-faq#limitations), [Secure Route Server](https://learn.microsoft.com/en-us/azure/route-server/secure-route-server) |
| Branch-to-branch | Route Server does **not** propagate routes between NVAs and VNet gateways by default, enable **branch-to-branch** explicitly if the NVAs must learn gateway routes (and note the 1,000-prefix advertisement cap toward ExpressRoute when enabled). | [Secure Route Server](https://learn.microsoft.com/en-us/azure/route-server/secure-route-server) |
| Route propagation control | Tag NVA-advertised routes with the `no-advertise` community (**65535:65282**) where propagation must be contained; avoid advertising routes carrying the Azure-reserved community `65517:65517`. | Same reference |
| DDoS | Enable Azure DDoS Protection on the Hub VNet, Route Server exposes public IPs for its management plane. | [Protect Route Server with DDoS](https://learn.microsoft.com/en-us/azure/route-server/tutorial-protect-route-server-ddos) |

### 12.3 AzureFirewallSubnet

| Constraint | Requirement |
|------------|-------------|
| NSG | Not supported |
| UDR | Supported. Two sanctioned uses: **(a)** forced tunneling (requires AzureFirewallManagementSubnet), and **(b)** a mandatory `0.0.0.0/0 → Internet` override route whenever on-prem advertises a default route over BGP/ExpressRoute, without it the firewall's own Internet egress (and SNAT path) is hijacked toward on-prem. |
| Minimum Size | /26 |

> **v4.9 fix**: v4.7 stated UDRs apply "only for forced tunneling". Per the [Azure Firewall known issues/limitations](https://learn.microsoft.com/en-us/azure/firewall/firewall-known-issues) and FAQ guidance, when a default route is learned from on-prem via BGP, you **must** attach a route table to AzureFirewallSubnet with `0.0.0.0/0` next-hop `Internet` to preserve direct egress. This design's `RT-GatewaySubnet` does not propagate a default route to the firewall subnet today (no Azure Firewall is deployed, NVAs are used), but the constraint matters if Azure Firewall is ever added alongside or instead of the NVAs.

### 12.4 AzureBastionSubnet

| Constraint | Requirement | Reference |
|------------|-------------|-----------|
| NSG | Required – must use exact rules per Section 9.1 | [Bastion NSG](https://learn.microsoft.com/en-us/azure/bastion/bastion-nsg) |
| UDR | Not supported | Same reference |
| Minimum Size | /26 | [Bastion Configuration](https://learn.microsoft.com/en-us/azure/bastion/configuration-settings) |
| Naming | Must be named exactly `AzureBastionSubnet` | Same reference |

### 12.5 DNS Resolver Subnets (Subnet-DNS-Inbound, Subnet-DNS-Outbound)

| Constraint | Requirement | Reference |
|------------|-------------|-----------|
| Delegation | Must be delegated to `Microsoft.Network/dnsResolvers` | [DNS Private Resolver](https://learn.microsoft.com/en-us/azure/dns/dns-private-resolver-overview) |
| NSG | Not required; conservative practice in this design is to omit. Current MS docs do not explicitly prohibit NSGs on DNS Resolver subnets; validate against live docs at deployment time. | Same reference |
| Other Resources | No other resources can be deployed | Same reference |
| Size | Minimum /28, Maximum /24 | Same reference |
| IPv6 | Not supported | Same reference |
| Separate Subnets | Inbound and Outbound endpoints require separate subnets | Same reference |
| ExpressRoute FastPath | **Not compatible**: do not enable FastPath on the ER gateway if on-prem uses the inbound endpoint for resolution | Same reference |
| Azure Lighthouse | Not compatible | Same reference |
| VNet encryption | Not supported on the hosting VNet | Same reference |

### 12.6 Default Outbound Access: Retirement & Private Subnets (v4.9)

Azure is retiring **default outbound access** (the implicit, unowned SNAT IP a VM gets when no explicit egress method exists). Per [Default outbound access in Azure](https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/default-outbound-access), **VNets created through an API version released after 31 March 2026 default to private subnets**: VMs in them get no implicit Internet egress at all.

**Impact on this design, none functional, by construction:**

| Subnet family | Explicit egress method already present |
|---|---|
| Spoke workloads | UDR `0.0.0.0/0 → ILB-NS-Outbound` (Section 7.1); NS NVA owns public IPs |
| Platform/Shared Services/Management | UDR `0.0.0.0/0 → ILB-NS-Outbound` (Sections 7.6-7.8) |
| NS NVA external NICs | Instance-level Public IPs (Section 6) |
| Gateway/Bastion/Firewall subnets | Azure-managed egress; not affected |

**Recommendations:**
1. Set **`defaultOutboundAccess = false`** explicitly on every new subnet (Terraform `azurerm_subnet.default_outbound_access_enabled = false`) so behaviour is identical regardless of API version, and intent is auditable.
2. Add an **Azure Policy** denying subnets with implicit outbound enabled, this turns a future platform behaviour change into a no-op.
3. Treat any workload that "worked in dev but not in the landing zone" as a likely implicit-egress dependency, the fix is the UDR/NVA path, never re-enabling default outbound.

### 12.7 Azure Policy Guardrail Catalog (v5.0, CAF policy-driven governance)

Every invariant in this document that a workload team could accidentally violate is enforced as **Azure Policy at the management-group scope** (Corp/Online inherit them, Section 1.2.2), complementing the Terraform plan gates in the fact-check report's Section L. Start from the [ALZ policy assignments](https://aka.ms/alz/policies) baseline, then layer these design-specific guardrails:

| # | Guardrail (effect) | Enforces | Scope |
|---|---|---|---|
| G-1 | **Deny** VNet creation whose address space is outside the IPAM-reserved CIDR for that subscription | Section 2/Section 4.4, no rogue address space, no overlaps | Corp + Online |
| G-2 | **Deny** subnets without an NSG (exempt: GatewaySubnet, RouteServerSubnet, AzureFirewall*, DNS-resolver delegated subnets) | Section 9, Sections 12.1-12.5 | All LZ MGs |
| G-3 | **Deny/Modify** route tables on GatewaySubnet containing `0.0.0.0/0`, or with BGP propagation disabled | Section 7.0, Section 12.1 | Connectivity |
| G-4 | **Deny** spoke route tables with BGP propagation **enabled**, and **DeployIfNotExists** the `RT-Spoke-Workloads` route set + association on every spoke subnet | Section 7.1, Section 8, Section 2.1 rule 2 | Corp + Online |
| G-5 | **Deny** VNet peerings missing the Section 4.3 flag combination (spoke side: `useRemoteGateways=true`, `allowForwardedTraffic=true`); **Deny** spoke↔spoke peerings entirely | Section 4.3, Section 4.3.3 | Corp + Online |
| G-6 | **Deny** subnets with `defaultOutboundAccess` enabled | Section 12.6 | All LZ MGs |
| G-7 | **Deny** public IP addresses in **Corp** landing zones (Online exempted for AppGW/LB frontends) | Section 1.2.2 Corp definition | Corp |
| G-8 | **Deny** DNS forwarding-ruleset rules named `.` (wildcard), and **Deny** Private DNS zone creation/links outside the Connectivity subscription | Section 3.2.1 wildcard caveat, Section 11.5 hub-only linkage | Tenant root / Connectivity |
| G-9 | **DeployIfNotExists** DDoS Network Protection plan association on every VNet | Section 1.1 DDoS row | All MGs |
| G-10 | **DeployIfNotExists** `privateEndpointNetworkPolicies = Enabled` on PE subnets | Section 11.4 | Corp + Online |
| G-11 | **Audit** NSG rules denying `AzurePlatformDNS` / `AzurePlatformIMDS` / `AzurePlatformLKM` service tags (legitimate only with documented justification) | Section 9 platform-VIP hygiene | All LZ MGs |
| G-12 | **Audit** any subnet delegated to `Microsoft.Network/dnsResolvers` carrying an NSG | Section 3.2/Section 12.5 conservative stance | Connectivity |

> Pair G-1…G-12 with **AVNM security admin rules** for the small set of absolute denies that must hold *even if a workload team edits its own NSGs* (e.g., deny inbound from Internet on Corp spokes): security admin rules evaluate **before** NSGs and cannot be overridden downstream.

---

## 13. Traffic Flow Diagrams

### 13.1 Spoke-to-Internet (Outbound)

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────┐
│ Spoke VM    │────▶│ ILB-NS-Outbnd│────▶│ NS NVA       │────▶│ Internet │
│ 10.4.x.x    │     │ 10.0.3.100   │     │ NAT + Inspect│     │          │
└─────────────┘     └──────────────┘     └──────────────┘     └──────────┘
      │                    
      │ UDR: 0.0.0.0/0     
      │ → 10.0.3.100       
      ▼                    
```

### 13.2 Spoke-to-Spoke (East-West)

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐     ┌─────────────┐
│ Spoke A VM  │────▶│ ILB-EW-Outbnd│────▶│ EW NVA       │────▶│ Spoke B VM  │
│ 10.4.0.x    │     │ 10.0.5.100   │     │ SNAT to      │     │ 10.4.4.x    │
│             │     │              │     │ 10.0.5.x     │     │             │
└─────────────┘     └──────────────┘     └──────────────┘     └─────────────┘
      │                    │                    │                    │
      │ UDR: 10.4.0.0/14   │                    │ VNet peering       │
      │ → 10.0.5.100       │                    │ (system routes)    │
      ▼                    ▼                    ▼                    ▼
                                                                     
┌─────────────────────────────────────────────────────────────────────────┐
│ Return Path: Spoke B replies to 10.0.5.x (NVA's SNAT IP)               │
│ UDR: 10.0.5.0/24 → Virtual Network (bypasses ILB, goes direct to NVA)  │
└─────────────────────────────────────────────────────────────────────────┘
```

> **Key**: The `To-NVA-Internal-Direct` route in `RT-Spoke-Workloads` ensures return traffic goes directly to the originating NVA instance, preserving session state in Active-Active scenarios.

### 13.3 On-Premises to Spoke

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌─────────────┐
│ On-Premises │────▶│ VPN/ER GW    │────▶│ ILB-EW-Outbnd│────▶│ EW NVA       │────▶│ Spoke VM    │
│ 192.168.x.x │     │ GatewaySubnet│     │ 10.0.5.100   │     │ Inspect+SNAT │     │ 10.4.x.x    │
└─────────────┘     └──────────────┘     └──────────────┘     └──────────────┘     └─────────────┘
      │                    │                    │                    │
      │ ExpressRoute/VPN   │ RT-GatewaySubnet   │ HA Ports           │ VNet peering
      │                    │ 10.4.0.0/14        │                    │ (system routes)
      │                    │ → 10.0.5.100       │                    │
      ▼                    ▼                    ▼                    ▼
```

> **Critical**: `RT-GatewaySubnet` (Section 7.0) must be associated with GatewaySubnet for this flow to work. Without it, on-premises traffic reaches spokes directly, bypassing NVA inspection, violating Zero Trust.

### 13.4 Platform-to-Spoke

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐     ┌─────────────┐
│ DNS Resolver│────▶│ RT-Platform  │────▶│ ILB-EW-Outbnd│────▶│ Spoke VM    │
│ 10.0.32.x   │     │ Workloads    │     │ 10.0.5.100   │     │ 10.4.x.x    │
└─────────────┘     └──────────────┘     └──────────────┘     └─────────────┘
      │                    │                    │
      │ UDR: 10.4.0.0/14   │                    │ EW NVA
      │ → 10.0.5.100       │                    │ Inspection
      ▼                    ▼                    ▼
```

### 13.5 DNS Resolution Flow

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐     ┌─────────────┐
│ Spoke VM    │────▶│ DNS Inbound  │────▶│ Azure DNS    │────▶│ Private DNS │
│ 10.4.x.x    │     │ 10.0.32.4    │     │              │     │ Zones       │
└─────────────┘     └──────────────┘     └──────────────┘     └─────────────┘
      │                                        │
      │ DNS Query                              │ If not Azure DNS
      │                                        ▼
                                        ┌──────────────┐
                                        │ DNS Outbound │──▶ On-Prem DNS
                                        │ 10.0.32.20   │    or External
                                        └──────────────┘
```

---

## 14. Visual Hierarchy

```
10.0.0.0/12 (Master Block, two regional /13s)
├── 10.0.0.0/13 (REGION 1)
│   ├── 10.0.0.0/16 (Platform LZ, Hub VNet declares ONLY the three /19s)
│   │   ├── 10.0.0.0/19 (Connectivity Hub)              [Hub VNet prefix 1]
│   │   │   ├── 10.0.0.0/26 (GatewaySubnet)
│   │   │   ├── 10.0.0.64/26 (RouteServerSubnet)
│   │   │   ├── 10.0.0.128/26 (AzureFirewallSubnet)
│   │   │   ├── 10.0.0.192/26 (AzureFirewallManagementSubnet) [Reserved]
│   │   │   ├── 10.0.1.0/26 (AzureBastionSubnet)
│   │   │   ├── 10.0.2.0/24 (Subnet-NS-External)
│   │   │   ├── 10.0.3.0/24 (Subnet-NS-Internal)
│   │   │   ├── 10.0.4.0/24 (Subnet-EW-External)
│   │   │   ├── 10.0.5.0/24 (Subnet-EW-Internal) ← ILB-EW-Outbound VIP here
│   │   │   ├── 10.0.6.0/24 (Subnet-Reserved-Hub) [Reserved]
│   │   │   ├── 10.0.7.0/24 (Subnet-NVA-Management)
│   │   │   └── 10.0.8.0/24 (Subnet-PrivateEndpoints-Hub)
│   │   ├── 10.0.32.0/19 (Shared Services)               [Hub VNet prefix 2]
│   │   │   ├── 10.0.32.0/28 (Subnet-DNS-Inbound) [Delegated, No NSG]
│   │   │   ├── 10.0.32.16/28 (Subnet-DNS-Outbound) [Delegated, No NSG]
│   │   │   ├── 10.0.33.0/24 (Subnet-DomainControllers)
│   │   │   ├── 10.0.34.0/24 (Subnet-Monitoring)
│   │   │   ├── 10.0.35.0/24 (Subnet-KeyVault)
│   │   │   └── 10.0.36.0/24 (Subnet-JumpServers)
│   │   ├── 10.0.64.0/19 (Management)                    [Hub VNet prefix 3]
│   │   │   ├── 10.0.64.0/24 (Subnet-AzureAutomation)
│   │   │   ├── 10.0.65.0/24 (Subnet-BackupVault)
│   │   │   └── 10.0.66.0/24 (Subnet-UpdateManagement)
│   │   └── 10.0.96.0–10.0.255.255 (plan-reserved, NOT VNet-assigned, Section 3.0)
│   ├── 10.1.0.0/16 + 10.2.0.0/15 (Platform growth, reserved, Section 2)
│   └── 10.4.0.0/14 (Application Landing Zones)
│       ├── 10.4.0.0/15 (Production, Medium /22 bottom-up, Large /20 top-down, Section 4.1.1)
│       ├── 10.6.0.0/16 (Development, Small /24)
│       └── 10.7.0.0/16 (Test/QA, Small /24)
└── 10.8.0.0/13 (REGION 2, reserved, identical internal template, Section 2.1)
```

---

## 15. Capacity Summary

### 15.1 Master Block (`10.0.0.0/12` = 1,048,576 addresses): two regional /13s

| Block | Addresses | Share of /12 |
|-------|-----------|--------------|
| **Region 1** (`10.0.0.0/13`) | 524,288 | 50% |
| ├─ Platform LZ (`10.0.0.0/16`) | 65,536 | 6.25% |
| ├─ Reserved, platform growth (`10.1.0.0/16` + `10.2.0.0/15`) | 196,608 | 18.75% |
| └─ Application LZs (`10.4.0.0/14`) | 262,144 | 25% |
| **Region 2, reserved** (`10.8.0.0/13`, identical template) | 524,288 | 50% |

### 15.2 Region 1 Platform LZ (`10.0.0.0/16` = 65,536 addresses)

| Measure | Addresses | Utilization |
|---------|-----------|-------------|
| **Declared on the Hub VNet** (three /19 prefixes, v5.0, Section 3.0) | 24,576 | 37.5% of the /16 plan block; **100% of VNet space is sectioned** |
| Actually subnetted today (sum of all defined subnets, Section 3) | 3,936 | 6.0% of the /16 / 16.0% of the VNet |
| Plan-reserved, **not VNet-assigned** (`10.0.96.0`–`10.0.255.255`) | 40,960 | 62.5%, added to the VNet as future /19 prefixes (+ peering resync, Section 2.2) or used for separate platform VNets |

> **v4.9 fix (retained)**: the pre-v4.9 "Used ≈ 8,192 / ~13%" matched neither measure. **v5.0 change**: the 24,576 figure moved from "committed sections inside a /16 VNet" to "the VNet's declared address space", the waste CAF warns about (idle /16 VNet space) is now zero by construction.

### 15.3 Application LZ Spoke Capacity (with Section 4.1.1 T-shirt mixing)

| Resource | Capacity |
|----------|----------|
| Production, Medium `/22` spokes (pure) | 128 max |
| Production, Large `/20` spokes (pure) | 32 max |
| Production, mixed | each Large consumes 4 Medium slots (e.g., 8 Large + 96 Medium) |
| Dev, Small `/24` spokes (`10.6.0.0/16`) | 256 max |
| Test, Small `/24` spokes (`10.7.0.0/16`) | 256 max |

### 15.4 Platform Scale Guardrails (v5.0, CAF): address space is *not* the binding constraint

Per the CAF [traditional-topology](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/traditional-azure-networking-topology) limits warning, two platform ceilings bind before the address plan does:

| Limit | Value | This design's consumption | Headroom verdict |
|---|---|---|---|
| **VNet peerings per VNet** (the Hub) | 500 | 1 per spoke (+1 if a Region-2 hub peers in) | **Binding constraint**: max ~499 concurrent spokes per regional hub, *below* the address plan's 640-spoke theoretical max. Track in IPAM; at ~400 spokes plan either a second hub VNet (from platform-growth space) or the Section 1.2.1 Virtual WAN re-evaluation. |
| **ER private-peering prefixes advertised Azure → on-prem** | 1,000 | 3 hub prefixes (v5.0, Section 3.0) + 1 per spoke (every spoke is single-prefix by design) | 3 + 499 = **502 ≤ 1,000**. By default each VNet advertises its own space, so **keep spokes single-prefix** (policy-level rule, enforced by G-1/Section 4.4 vending). Where many hubs share the same ExpressRoute circuits (Section 2.1) or the count climbs, set the gateway's **Advertised Gateway Prefixes** (`summarizedGatewayPrefixes`) so the VPN/ER gateway advertises a *summary* of the hub address space + covered spoke prefixes instead of every individual prefix, the sanctioned lever to stay under the 1,000-prefix limit without renumbering ([advertised gateway prefixes](https://learn.microsoft.com/en-us/azure/virtual-network/advertised-gateway-prefixes-overview)). |

| **UDRs per route table** (v5.2/F1) | 400 default / **1,000 AVNM-managed** | per-spoke exact routes: 1 route per spoke in each hub-side steering table | At > 400 spokes the hub-side tables must be AVNM-managed ([UDR management](https://learn.microsoft.com/azure/virtual-network-manager/concept-user-defined-route), Microsoft names this exact hub-and-spoke-per-spoke-firewall-routes scenario); the ≈ 499-spoke ceiling stands only with AVNM. |

> **Design rule derived**: the practical Region-1 ceiling is **≈ 499 spokes**, not 640. The Section 4 pools deliberately over-provision address space relative to this ceiling, that is correct CAF behaviour (address space is cheap to reserve, impossible to retrofit), not waste.

> **v5.1 extension**: Section 24 adds the per-tier NVA-subnet capacity guardrails introduced with NVA group chains (Section 19), the 96 static-NIC ceiling, the 155 chained-group VIP-ladder ceiling, and the exact 251-address-per-/24 check.

---

## 16. CIDR Quick Reference

| CIDR | Addresses | Typical Use |
|------|-----------|-------------|
| /28 | 16 (11 usable) | DNS Resolver endpoints |
| /26 | 64 (59 usable) | Gateway subnets, Bastion |
| /25 | 128 (123 usable) | Application tiers |
| /24 | 256 (251 usable) | Standard subnets |
| /22 | 1,024 (1,019 usable **only as one flat subnet**; templated spoke per Section 4.2 = 487 usable across its five subnets) | Standard spoke VNet |
| /19 | 8,192 | Hub sections |
| /16 | 65,536 | Platform Landing Zone |
| /14 | 262,144 | Application Landing Zones |
| /12 | 1,048,576 | Master allocation |

---

## 17. Implementation Checklist

### Phase 0: CAF Governance Prerequisites (v5.0)
- [ ] Confirm the Section 1.2.1 topology decision record still holds (regions ≤ 2, branches < 30, ER primary), re-run if any trigger fired
- [ ] Validate `<on-prem-supernet>` and all individually advertised on-prem prefixes do **not** overlap `10.0.0.0/12` (Section 2.2); record VPN-NAT exceptions per overlapping legacy site
- [ ] Deploy **Azure IPAM** and seed it with the Section 2 regional /13 template; wire the reservation API into subscription vending (Section 4.4)
- [ ] Create the **Connectivity subscription** under the Connectivity MG; confirm Corp/Online MG hierarchy and ALZ baseline policy assignments are in place (Section 1.2.2)
- [ ] Deploy the single **DDoS Network Protection plan** in the Connectivity subscription (Section 1.1)
- [ ] Assign the Section 12.7 guardrail policies (G-1…G-12) at the appropriate MG scopes
- [ ] Decide AVNM adoption: connectivity configuration for hub-and-spoke peering at scale, security-admin rules for absolute denies (Section 4.3 note, Section 12.7)
- [ ] Create region-scoped resource groups for hub resources (Section 2.1 rule 4); enable Network Watcher + network insights in every in-scope region

### Phase 1: Foundation
- [ ] Lock down SKU choices per Section 1.1 and document any deviation
- [ ] Confirm on-premises supernet(s) and replace `<on-prem-supernet>` placeholders in Sections 7.1 and 7.6
- [ ] Create Hub VNet with **exactly three address prefixes**: `10.0.0.0/19`, `10.0.32.0/19`, `10.0.64.0/19` (Section 3.0; **not** the full `/16`, CAF), and associate the DDoS plan from Phase 0
- [ ] Create all hub subnets per Section 3 (including DNS subnets with delegation `Microsoft.Network/dnsResolvers`), each with `defaultOutboundAccess = false` (Section 12.6)
- [ ] Verify VNet encryption is **disabled** on the Hub VNet (DNS Private Resolver requirement)
- [ ] Deploy VPN/ExpressRoute Gateway at the SKU chosen in Section 1.1, note the gateway will advertise **3 hub prefixes** to on-prem (Section 15.4)
- [ ] **Verify** ExpressRoute FastPath is **disabled** if DNS Private Resolver is the on-prem → PE resolution path (Section 3.2.1)
- [ ] Create `RT-GatewaySubnet` with spoke/platform routes (Section 7.0) and associate to GatewaySubnet
- [ ] **Verify** RT-GatewaySubnet has BGP propagation **enabled** and does NOT contain a `0.0.0.0/0` route
- [ ] Deploy Azure Bastion with NSG-Bastion (Section 9.1), confirm the protocol split: `Any` for `AllowBastionHostCommunication`, `AllowSshRdpOutbound`, `AllowBastionCommunication`, `AllowHttpOutbound`; `Tcp` for the remaining 4 (per the MS summary table; see Section 9.1 validation notes on the doc's internal conflict)
- [ ] Deploy Azure Private DNS Resolver with inbound and outbound endpoints

### Phase 2: Security Infrastructure
- [ ] Deploy North-South NVAs (active-active) with 2 NICs each
- [ ] Deploy East-West NVAs (active-active) with 2 NICs each
- [ ] Configure NVA loopback interfaces with ILB VIPs (Section 6.4)
- [ ] Configure East-West NVA SNAT for spoke traffic (Section 6.5)
- [ ] **Configure NVA firewall rules for DNS Resolver egress** per Section 3.2.2 (UDP/TCP 53 from `10.0.32.16/28` via NS and/or EW NVAs)
- [ ] Create all ILBs with HA Ports and Floating IP enabled
- [ ] Configure health probes (TCP 443 or custom port)
- [ ] Create Application Security Groups (ASGs)

### Phase 3: Routing
- [ ] Create all route tables per Section 7
- [ ] **Verify** NVA egress routes use `Virtual Network` not ILB (RT-EW-External, RT-EW-Internal)
- [ ] **Verify** the `To-NVA-Internal-Direct*` routes exist in RT-Spoke-Workloads (one per NVA internal subnet, incl. Section 19 chain segments)
- [ ] **Verify** chain-segment route tables resolve hop-by-hop to the next element (incl. the Azure Firewall slot) per Section 19.5, `tests/run.js` automates this
- [ ] **Verify** RT-EW-Internal has BGP propagation **enabled** (v4.6 change, required for on-prem return path)
- [ ] **Verify** RT-NS-External has BGP propagation **disabled** (v4.6 change)
- [ ] Associate route tables to subnets
- [ ] Verify BGP propagation settings per Section 8
- [ ] Test routing with traceroute/packet capture

### Phase 4: Network Security
- [ ] Create all NSGs per Section 9
- [ ] Verify AllowAzureLoadBalancer rules on all NVA subnets
- [ ] Associate NSGs to subnets (DNS Resolver subnets, see Section 12.5 for current guidance)
- [ ] Enable **VNet flow logs** (not NSG flow logs), **NSG flow logs are retired**: no *new* NSG flow logs can be created after 30 Jun 2025, and the feature retires 30 Sep 2027 ([retirement notice](https://azure.microsoft.com/updates/v2/Azure-NSG-flow-logs-Retirement)). Enable [VNet flow logs](https://learn.microsoft.com/en-us/azure/network-watcher/vnet-flow-logs-overview) at the **Hub and every spoke VNet** (one resource per VNet, no per-NSG/per-NIC duplication across the many subnets and NSGs in this design), and turn on **Traffic Analytics**. VNet flow logs additionally record **AVNM security-admin-rule** allow/deny (this design uses them, Section 12.7), plus gateway traffic and VNet-encryption status. Note `Subnet-DNS-Inbound/Outbound` (DNS Private Resolver) are **not** supported by flow logs, capture resolver-egress diagnostics on the NVA instead (Section 3.2.2). If migrating an existing estate, **disable NSG flow logs before enabling VNet flow logs** on the same workloads to avoid duplicate capture and cost.
- [ ] Configure ASG membership for VMs

### Phase 5: Spoke Deployment
- [ ] Reserve the spoke CIDR via the **IPAM API in the vending pipeline** at the requested T-shirt size (Section 4.1.1, Section 4.4), never hand-pick addresses
- [ ] Create spoke VNet from the matching template (Section 4.2 Medium/Large, Section 4.2.1 Small) as a **single-prefix** VNet (Section 15.4), with the DDoS plan associated and `defaultOutboundAccess = false` on every subnet
- [ ] Peer spoke to hub, **explicitly set all flags per Section 4.3** (or let the AVNM hub-and-spoke connectivity configuration create it):
  - [ ] Spoke side: `UseRemoteGateways = true`, `AllowForwardedTraffic = true`, `AllowVirtualNetworkAccess = true`
  - [ ] Hub side: `AllowGatewayTransit = true`, `AllowForwardedTraffic = true`, `AllowVirtualNetworkAccess = true`
  - [ ] Confirm spoke does **not** also host its own VPN/ER gateway (mutually exclusive with `UseRemoteGateways = true`)
- [ ] Apply RT-Spoke-Workloads to all spoke subnets, verify it carries the hub's exact /19 prefixes, To-Bastion-Direct, and one To-NVA-Internal-Direct per NVA internal subnet (v5.2 Section 7.1)
- [ ] **Vending step (v5.2/F1)**: add the new spoke's exact-prefix route to every hub-side steering table (RT-GatewaySubnet, RT-Platform-Workloads, RT-Management, RT-NVA-Mgmt, RT-NS-External, RT-AzureFirewallSubnet where present), and remove it on decommission; at scale manage these via AVNM UDR configurations (Section 15.4)
- [ ] Apply appropriate NSGs to spoke subnets
- [ ] Configure Private Endpoints per Section 11
- [ ] **Set** `privateEndpointNetworkPolicies = Enabled` on PE subnets (or `NetworkSecurityGroupEnabled` if only NSG enforcement is needed)
- [ ] Online spokes only: deploy the application's **AppGW/WAF inside the spoke** (Section 1.2.2, Section 5 inbound note), never in the hub

### Phase 6: DNS & Private Endpoint Resolution
- [ ] Create every Private DNS zone listed in Section 11.5.1 for the services in scope
- [ ] **Link every `privatelink.*` zone to the Hub VNet**: without this, PEs silently resolve to public IPs
- [ ] Configure spoke VNets to use `10.0.32.4` as their DNS server (custom DNS at VNet level)
- [ ] Configure DNS forwarding ruleset on the outbound endpoint for on-prem domains, and **link the ruleset to the Hub VNet** (spoke links are ignored because spokes use custom DNS, see Section 18.9)
- [ ] If a wildcard `.` forwarding rule exists in the ruleset, confirm the resolver and the ExpressRoute gateway are not constrained by the wildcard caveat in Section 3.2.1
- [ ] Configure on-prem DNS conditional forwarders → `10.0.32.4` for every `privatelink.*` zone in use (Section 11.5.3)
- [ ] Validate resolution from a spoke VM: `nslookup <pe-fqdn>` must return the **private** IP, not the public IP
- [ ] Validate resolution from on-prem: `nslookup <pe-fqdn>` from on-prem must also return the private IP

### Phase 7: Validation
- [ ] Test Internet outbound from spoke
- [ ] Test spoke-to-spoke communication (verify SNAT return path)
- [ ] Test spoke-to-on-premises communication (every documented on-prem prefix)
- [ ] Test on-premises-to-spoke communication (verify the EW NVA inspects, return path works)
- [ ] Test platform-to-spoke communication
- [ ] Verify NVA inspection logs
- [ ] Verify symmetric routing (same NVA for request/response)
- [ ] Test ILB health probe functionality
- [ ] Validate DNS resolution for Private Endpoints (from spoke, hub, and on-prem)
- [ ] Verify SNAT is working for East-West traffic
- [ ] **Verify** no routing loops on NVA subnets
- [ ] Test DNS resolution from spokes to Azure Private DNS Zones
- [ ] Test DNS forwarding to on-premises DNS servers

---

## 18. Troubleshooting Guide

### 18.1 ILB Health Probe Failures

**Symptom**: NVAs marked unhealthy, traffic not flowing

**Checklist**:
1. Verify `AllowAzureLoadBalancer` NSG rule exists (source: `AzureLoadBalancer` service tag)
2. Verify NVA is listening on probe port
3. Check NVA firewall allows probe traffic
4. Verify probe port matches ILB configuration

### 18.2 Asymmetric Routing / SNAT Return Failures

**Symptom**: Connections timeout, stateful inspection fails, ~50% packet loss in Active-Active

**Checklist**:
1. Verify HA Ports enabled on all ILBs
2. Verify `To-NVA-Internal-Direct` route (`10.0.5.0/24` → `Virtual Network`) exists in RT-Spoke-Workloads
3. Confirm SNAT is configured on East-West NVA for spoke-to-spoke traffic
4. Verify NVA SNATs to its internal interface IP (`10.0.5.x`)
5. Check BGP propagation is disabled where required
6. Verify NVA session tables

### 18.3 NVA Routing Loop (Sandwich Loop)

**Symptom**: Traffic loops indefinitely between NVA interfaces, TTL expires, no connectivity

**Checklist**:
1. Verify RT-EW-External has `To-Spokes` → `Virtual Network` (NOT to ILB)
2. Verify RT-EW-Internal has `To-Spokes` → `Virtual Network` (NOT to ILB)
3. NVA egress must use VNet peering (system routes), not route back to its own ILB
4. Use `traceroute` from NVA to spoke to confirm path

### 18.4 Spoke Cannot Reach Internet

**Checklist**:
1. Verify RT-Spoke-Workloads has `0.0.0.0/0` → `10.0.3.100`
2. Verify NSG allows outbound traffic
3. Verify NS NVA is healthy
4. Check NVA NAT configuration

### 18.5 Platform Cannot Reach Spokes

**Checklist**:
1. Verify RT-Platform-Workloads is applied to platform subnets
2. Verify route `10.4.0.0/14` → `10.0.5.100` exists
3. Verify EW NVA allows platform-to-spoke traffic
4. Check NSG-EW-Internal allows platform source IPs

### 18.6 NVA Dropping Packets with Floating IP

**Symptom**: Traffic reaches NVA but is dropped

**Checklist**:
1. Verify loopback interface configured with ILB VIP addresses
2. Verify NVA OS is listening on the VIP (not just NIC IP)
3. Check NVA routing table includes VIP as local address
4. Verify NVA firewall policy allows traffic to VIP destinations

### 18.7 Azure Bastion Deployment Fails

**Symptom**: Bastion deployment or connectivity fails

**Checklist**:
1. Verify NSG-Bastion has all required rules (Section 9.1)
2. Verify subnet name is exactly `AzureBastionSubnet`
3. Verify subnet size is at least /26
4. Check no UDR is associated with AzureBastionSubnet
5. Verify all outbound rules allow required destinations

### 18.8 DNS Private Resolver Deployment Fails

**Symptom**: Cannot create inbound or outbound endpoints

**Checklist**:
1. Verify subnets are delegated to `Microsoft.Network/dnsResolvers`
2. Confirm DNS Resolver subnets have **no NSG attached** (this design omits them by choice); if one was attached experimentally, remove it and retry before debugging further
3. Verify no other resources exist in the delegated subnets
4. Verify subnet size is at least /28
5. Verify subnets are not IPv6-enabled
6. Verify inbound and outbound endpoints use separate subnets
7. Verify the VNet does not have encryption enabled

### 18.9 DNS Resolution Not Working from Spokes

**Symptom**: VMs cannot resolve Azure Private DNS Zone records

**Checklist**:
1. Verify spoke VNet DNS servers point to DNS Resolver inbound endpoint IP (`10.0.32.4`)
2. Verify Private DNS Zones are linked to Hub VNet
3. Verify the DNS forwarding ruleset is linked to the **Hub VNet** (the VNet hosting the resolver). Linking it to spoke VNets has **no effect** here: per the resolver's documented query process, a VNet configured with **custom DNS servers** (as all spokes are, pointing at `10.0.32.4`) does **not** consult its own ruleset links, the query is processed by the ruleset linked to the resolver's VNet.
4. Check NVA allows DNS traffic (UDP/TCP 53) from spokes to DNS subnets
5. DNS Resolver subnets use RT-Platform-Workloads for routing

### 18.10 Private Endpoint NSG Rules Not Working

**Symptom**: NSG rules on Private Endpoint subnet are ignored

**Checklist**:
1. Verify `privateEndpointNetworkPolicies` is set to **Enabled** on the subnet
2. If set to **Disabled**, NSG rules will not be enforced on Private Endpoint traffic
3. Update subnet properties and re-test

---

## 19. NVA Group Chains

### 19.1 Model

Each inspection tier (North-South, East-West, or the single combined tier) holds an **ordered list of NVA groups**. A group is an independently deployed appliance cluster: a named set of 1–3 VM instances behind a Standard ILB, or a VMSS Flex scale set behind a Standard ILB.

| Property | Rule (v5.2, fabric-routed cascade) |
|---|---|
| Order | Groups are **chained by sort order**. Group 1 is the **entry point**. |
| Workload routing | **Every workload/gateway UDR references only the entry group's hop.** Later hops are reached exclusively through the per-segment subnet route tables below. |
| Entry hop | Group 1 keeps the v5.0 anchor: `ILB-NS-Outbound = <NS-internal>.100`, `ILB-EW-Outbound = <EW-internal>.100`, `ILB-FW-Outbound` for the single tier. |
| Segment subnets | **Each chained group i ≥ 2 owns a dedicated /24 internal subnet** (`Subnet-<tier>-Internal-i`, allocated from `10.0.9.0/24` upward, Section 3.1) with its VIP at that subnet's `.100` (`lbi-<tier>-<group>` per CAF). A chained East-West/single tier adds **one** `Subnet-EW-Forward`/`Subnet-FW-Forward` hosting group 1's forward NICs. Standalone groups stay in group 1's subnet on the VIP ladder (`.101+`). |
| Forwarding contract | **Segment i → i+1 steering is a per-subnet UDR**, not appliance configuration: NS segments carry `0.0.0.0/0 → <next hop>`; EW/single segments carry the lateral prefix set (one exact route per spoke + Shared /19 + Management /19 + Hub-PE /24 + on-prem) → `<next hop>` (Section 19.5). The **last** group egresses normally (NS: external NICs → Internet; EW: Virtual Network to destination, BGP on for on-prem). **Why**: Azure forwards on the destination IP against the subnet's effective routes, a guest-OS next hop pointing at a VIP in the *same* subnet is **not honored** ([route selection](https://learn.microsoft.com/azure/virtual-network/virtual-networks-udr-overview#how-azure-selects-routes-for-traffic-routing)), and Microsoft's UDR guidance requires an NVA to sit in a **different subnet** than the resources routed through it. The v5.1 same-subnet contract was unimplementable (F2): hops 2+ never received traffic. |
| Symmetry | **Every group SNATs to the NIC it forwards from.** Each chain segment then satisfies the v5.0 Section 6.7 invariant independently (both directions of each segment traverse the same ILB/instance), so returns retrace the chain hop-by-hop; spoke route tables carry one `To-NVA-Internal-Direct` route per NVA internal subnet (Section 7.1). A group that does not SNAT breaks its segment's state table, hard requirement, identical in spirit to Section 6.5. |

### 19.2 Address law per segment subnet 

Usable host range of a /24: `.4 – .254` (Azure reserves `.0–.3` and `.255`; 251 usable, v5.0 Section 16). The law applies **per subnet**:

| Range | Purpose | Capacity |
|---|---|---|
| `.4 – .99` | **Static NVA NICs** of the groups resident in that subnet (group 1's subnet also hosts standalone groups) | **96 static NICs per subnet, hard limit** |
| `.100` | The resident chained group's **VIP** | 1 per segment subnet |
| `.101 – .254` | **VIP ladder for standalone groups** co-resident in group 1's subnet | **154 standalone groups, hard limit** |
| remaining free addresses | **VMSS dynamic NICs** (Azure-assigned) | `251 − statics − VIPs` |

Capacity equations, checked exactly by the tool:

```
per segment subnet:  need = Σ static VM NICs + Σ ILB VIPs + Σ VMSS max instances ≤ 251
per segment subnet:  Σ static VM NICs ≤ 96   (beyond this, the group must be VMSS)
per tier:            chained groups ≤ free /24s in the Connectivity /19 (section-exhaustion check)
```

**Worked example (the Test scenario)**: NS = 4 chained groups × 2 VMs → `Subnet-NS-Internal` + `-2/-3/-4` (10.0.9–11), each at 3/251 (2 statics + 1 VIP). EW = 3 chained groups + `Subnet-EW-Forward` (10.0.12–14). Six chain subnets consume 6 of the ~23 spare /24s in the Connectivity /19.

**Cross-tier**: the shared constraint is `Subnet-NVA-Management` (/24): **all static instances across all tiers ≤ 251 management NICs**. VMSS management NICs are dynamic.

> **Deployment-order rule**: create the ILB frontends (VIPs) and static NICs **before** any VMSS scales out, so Azure's dynamic allocator can never grab a planned address.

### 19.3 When NOT to chain: Microsoft-aligned decision record

Per the [HA-NVA guide](https://learn.microsoft.com/azure/architecture/networking/guide/network-virtual-appliance-high-availability), the ILB-sandwich is Microsoft's reference for private inline NVAs, chains of 2–3 groups (e.g., vendor firewall → dedicated IDS/IPS → SSL inspector) are an accepted extension of it. **v5.2: the tool now emits a WARN whenever a tier's chain (including a chained Azure Firewall) exceeds 3 elements.** Beyond that, re-evaluate:

1. **Gateway Load Balancer** is Microsoft's purpose-built service for transparent NVA insertion on **public/North-South** paths (bump-in-the-wire, no UDR management). Prefer it over deep NS chains when the NVA vendor supports GWLB.
2. Every chain hop adds latency, an ILB, and an operational failure domain. If two groups run the **same** vendor/function, merge them into one group (scale instances instead).
3. **Azure Firewall + NVA** is already covered as a 2-element chain (Section 20), don't model the firewall as an NVA group.

### 19.4 Standalone groups (explicit-proxy pattern)

A group may be marked **standalone**: it keeps its name, instances/VMSS, ladder VIP and subnet capacity, but it is **excluded from the chain**: no UDR ever points at it. This models appliances that clients address directly, the classic case being an **explicit forward proxy** (browsers/PAC files target the proxy VIP on its port; the proxy then egresses through the tier chain or its own public IP per its configuration). Rules: at least **one chained group per tier** must remain (the entry); standalone groups don't shift Azure Firewall chain slots; capacity math counts them normally.

### 19.5 Chain-segment route tables (normative)

For a tier with chained elements `E1 … En` (NVA groups and, optionally, one Azure Firewall slot, Section 20):

| Subnet | Route table | Routes | BGP |
|---|---|---|---|
| `Subnet-NS-Internal` (E1, North-South) | `RT-NS-Internal` | `0.0.0.0/0 → hop(E2)`, or **no routes** when n = 1 | Disabled |
| `Subnet-NS-Internal-i` (mid segments) | `RT-NS-Internal-i` | `0.0.0.0/0 → hop(E[i+1])` | Disabled |
| `Subnet-NS-Internal-n` (last) | `RT-NS-Internal-n` | *(empty, egress via external NICs)* | Disabled |
| `Subnet-EW-Internal` (E1 client side, East-West) | `RT-EW-Internal` | unchanged v5.0 anchor: `To-Spokes (VN)`, `To-Hub (VN)` | Enabled |
| `Subnet-EW-Forward` (E1 forward side) | `RT-EW-Forward` | lateral set → `hop(E2)`: one exact route per spoke + Shared `/19` + Management `/19` + Hub-PE `/24` + on-prem | Disabled |
| `Subnet-EW-Internal-i` (mid segments) | `RT-EW-Internal-i` | lateral set → `hop(E[i+1])` | Disabled |
| `Subnet-EW-Internal-n` (last) | `RT-EW-Internal-n` | `To-Spokes (VN)`, `To-Hub (VN)`, delivers via peering | Enabled |
| `AzureFirewallSubnet` (firewall slot, non-last) | `RT-AzureFirewallSubnet` | NS chain: `0.0.0.0/0 → hop(next)`; EW/single chain: lateral set (+ `0.0.0.0/0` on the single tier) → `hop(next)` | Disabled |

Design rationale, mirrored from the F2 analysis: only group 1 both **forwards** spoke-destined traffic (to E2) and **delivers** toward spoke clients (returns), those two intents collide on one subnet, hence the dedicated forward subnet on the EW/single tier. Mid segments never deliver to clients; the last segment never forwards, both are single-subnet. Returns between segments target NVA NIC addresses (hub-internal) and ride system routes plus NSG flow state; returns to workloads ride the spoke RTs' `To-NVA-Internal-Direct` exemptions (Section 7.1).

---

## 20. Chained Azure Firewall

The v5.0 deviation register kept `AzureFirewallSubnet` as a reserved "exit ramp". v5.1 promotes it to three deployable patterns, all keeping the NVA tiers intact:

| Pattern | Routing | SNAT rule |
|---|---|---|
| **Chained into N-S (dual-tier)** | Workload `0.0.0.0/0` → AzFW (`.132` private IP) → `RT-AzureFirewallSubnet` `0/0` → NS entry VIP → Internet | AzFW SNATs to its private range so internet returns retrace it ([SNAT doc](https://learn.microsoft.com/azure/firewall/snat-private-range)) |
| **Chained into E-W (dual-tier)** | Spoke/on-prem lateral routes + `RT-GatewaySubnet` → AzFW → `RT-AzureFirewallSubnet` (spokes/shared/mgmt) → EW entry VIP | AzFW keeps **default no-SNAT** so the EW NVAs see true sources; the EW tier's own SNAT (Section 6.5) preserves return symmetry, returns intentionally bypass the firewall (forward-leg policy) |
| **Chained on the single tier** | Everything → AzFW → `RT-AzureFirewallSubnet` (0/0 + spokes + shared + mgmt) → `ILB-FW-Outbound` | As N-S row |
| **Azure Firewall only** | v5.0 native exit ramp executed: firewall takes both roles | `255.255.255.255/32` (always-SNAT) for spoke↔spoke (Section 6.5) |

**Chain position**: the firewall may occupy **any slot** in the tier's group chain (1 = entry … N+1 = last). Workload route tables always target chain slot 1, whichever element owns it. **v5.2 (F2)**: every hand-off is a fabric-routed per-subnet UDR, mid-chain, `RT-AzureFirewallSubnet` forwards to the next element's hop, and the **preceding group's segment route table** (Section 19.5) steers to the firewall's private IP (never appliance OS next hops, which Azure does not honor across a shared subnet). Last slot: **no** `RT-AzureFirewallSubnet`, the firewall egresses natively (Internet: SNAT to its public IP; East-West: VNet system/peering routes), and the preceding segment's RT targets the firewall IP.

Rules carried over: only **one** `AzureFirewallSubnet` per VNet; `AzureFirewallManagementSubnet` keeps Azure-managed routing (no UDR); `RT-AzureFirewallSubnet` runs with BGP propagation **disabled**; the NVA tier's internal NSG gains `AllowFromAzureFirewall` (source = the /26).

---

## 21. VMSS-based NVAs

| Aspect | Rule |
|---|---|
| Orchestration | VMSS **Flexible**, zone-spread, behind the group's Standard ILB (HA ports). |
| Addressing | Instance NICs are **dynamic**: the plan reserves *capacity* (max instances), never specific addresses. The **VIP is the only stable address**; routing never changes on scale events. |
| Scale floor | **min ≥ 2.** A floor of 1 is a periodic single point of failure (scale-in, zone loss), the tool warns. |
| Image contract | The vendor image must join the ILB backend pool on scale-out, configure the VIP loopback (Section 6.4), and SNAT via its internal NIC. Validate Section 17 Phase-7 symmetry tests after every scale event. |
| Management | VMSS management NICs are dynamic in `Subnet-NVA-Management`; the NSG attaches via the scale-set NIC profile. |

---

## 22. Catalog-driven spokes & CAF naming

### 22.1 Free-form spoke catalog
Spokes are a list of `{ name, environment, size }`, environments are **labels, not pools**. Sizes follow the Section 4.1.1 T-shirt catalog (S /24 · M /22 · L /20, extensible via `config.js`).

- **Reference mode** allocates **by size** into the unchanged v5.0 pools: M+L → `10.4.0.0/15` (two-pointer: M bottom-up, L top-down), S → `10.6.0.0/16` with `10.7.0.0/16` as overflow. Custom prefixes require Auto mode.
- **Auto mode** creates one right-sized pool per environment (next-power-of-two, optional ≈2× headroom); prefixes ≤ /20 fill top-down, the rest bottom-up by ascending prefix.

### 22.2 Naming convention ([CAF abbreviations](https://learn.microsoft.com/azure/cloud-adoption-framework/ready/azure-best-practices/resource-abbreviations))

| Resource | Pattern | Example |
|---|---|---|
| Hub VNet | `vnet-hub-<region>` | `vnet-hub-westeurope` |
| Spoke VNet | `vnet-<name>-<env>-<region>` (duplicates get `-002…`) | `vnet-crm-prod-westeurope` |
| Spoke subnet | `snet-<tier>-<name>-<env>-<region>` | `snet-web-crm-prod-westeurope` |
| Spoke NSG | `nsg-<tier>-<name>-<env>-<region>` | `nsg-web-crm-prod-westeurope` |
| Spoke route table | `rt-<name>-<env>-<region>` (the RT-Spoke-Workloads route set, instantiated per spoke) | `rt-crm-prod-westeurope` |
| NVA instance | `nva-<group>-NN` (individually overridable) | `nva-fortigate-01` |
| NVA scale set | `vmss-<group>` | `vmss-waf` |
| Chain-hop ILB | `lbi-<tier>-<group>` (entry ILBs keep the v5.0 names) | `lbi-ns-waf` |

Platform objects keep their v5.0 identifiers (`RT-GatewaySubnet`, `NSG-Bastion`, `ILB-NS-Outbound`, Azure-mandated subnet names).

### 22.3 Configuration file
All selectable values live in `web/config.js` (`AZIP_CONFIG`): Azure regions, environments, spoke sizes (with prefix), allowed VM counts per NVA group (default 1–3; more ⇒ VMSS). Editing the file updates dropdowns, naming and sizing, no code change.

---

## 23. Operational gating rules (tool behaviour)

1. **No on-prem network ⇒ no hybrid connectivity**: ER/VPN are disabled and the GatewaySubnet is not deployed (reference mode keeps the slot Reserved). Model point-to-site-only entry with a placeholder on-prem prefix.
2. On-prem present but no gateway selected ⇒ prefixes are planned but flagged unreachable; **no connectivity line** is drawn.
3. ER + VPN together ⇒ ER is the primary (solid), VPN the backup (dashed), matching v5.0 Section 1.1's "VPN is backup only".
4. **Region-2 reservation** (`10.8.0.0/13` in the reference plan): an equal-sized block kept unallocated so a second region can deploy the identical template later without renumbering, purely an IP-plan reservation, nothing is created in Azure (CAF: plan per region, non-overlapping).

---

## 24. Updated capacity guardrails

| Limit | Value | Notes |
|---|---|---|
| Hub VNet peerings | 500 (practical ≈ 499 spokes) | unchanged from v5.0 |
| ER private-peering advertised prefixes | 1,000 | hub prefixes + 1 per spoke |
| Static NVA NICs per tier subnet | **96** (`.4–.99`) | new, beyond this, use VMSS |
| Chained groups per tier | **155** (VIP ladder `.100–.254`) | new, practical designs: ≤ 20 |
| Tier subnet total (statics + VIPs + VMSS max) | **251** | new, exact check per /24 |
| Static mgmt NICs (all tiers) | **251** (`Subnet-NVA-Management` /24) | unchanged |
| Chain-segment subnets per tier | free /24s in the Connectivity `/19` (≈ 23 in the reference layout) | **v5.2**: each chained group ≥ 2 consumes one /24 (+1 forward subnet for EW/single); section-exhaustion check errs |
| UDRs per route table | **400** default / **1,000** AVNM-managed | **v5.2 (F1)**: per-spoke exact routes add 1 route/spoke to every hub-side steering table; tool warns > 400, errs > 1,000 |

---

## 25. Microsoft Documentation References

| Topic | URL |
|-------|-----|
| Azure DNS Private Resolver | https://learn.microsoft.com/en-us/azure/dns/dns-private-resolver-overview |
| DNS Private Resolver, Hybrid Resolution | https://learn.microsoft.com/en-us/azure/dns/private-resolver-hybrid-dns |
| Azure Bastion NSG Requirements | https://learn.microsoft.com/en-us/azure/bastion/bastion-nsg |
| GatewaySubnet Requirements (VPN) | https://learn.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-about-vpn-gateway-settings#gateway-subnet |
| ExpressRoute Gateway Subnet | https://learn.microsoft.com/en-us/azure/expressroute/expressroute-about-virtual-network-gateways#gateway-subnet |
| Route Server FAQ / Limitations | https://learn.microsoft.com/en-us/azure/route-server/route-server-faq |
| Azure Firewall SNAT Private Ranges | https://learn.microsoft.com/en-us/azure/firewall/snat-private-range |
| Private Endpoint Network Policies | https://learn.microsoft.com/en-us/azure/private-link/disable-private-endpoint-network-policy |
| Private Endpoint DNS Integration | https://learn.microsoft.com/en-us/azure/private-link/private-endpoint-dns |
| Virtual Network Peering Overview | https://learn.microsoft.com/en-us/azure/virtual-network/virtual-network-peering-overview |
| Virtual Network UDR / Custom Routes | https://learn.microsoft.com/en-us/azure/virtual-network/virtual-networks-udr-overview |
| Subnet Delegation Overview | https://learn.microsoft.com/en-us/azure/virtual-network/subnet-delegation-overview |
| AD Firewall Port Requirements | https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/config-firewall-for-ad-domains-and-trusts |
| HA NVA Patterns (flow symmetry) | https://learn.microsoft.com/en-us/azure/architecture/networking/guide/network-virtual-appliance-high-availability |
| Default Outbound Access Retirement | https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/default-outbound-access |
| Azure Firewall Known Issues / Limitations | https://learn.microsoft.com/en-us/azure/firewall/firewall-known-issues |
| Secure Route Server Deployment | https://learn.microsoft.com/en-us/azure/route-server/secure-route-server |
| Dsv5 VM Series (network bandwidth) | https://learn.microsoft.com/en-us/azure/virtual-machines/sizes/general-purpose/dsv5-series |
| **CAF, What is an Azure landing zone?** | https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/ |
| **CAF, ALZ design principles** | https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/design-principles |
| **CAF, Network topology & connectivity design area** | https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/design-area/network-topology-and-connectivity |
| **CAF, Define an Azure network topology** | https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/define-an-azure-network-topology |
| **CAF, Traditional Azure networking topology** | https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/traditional-azure-networking-topology |
| **CAF, Plan for IP addressing** | https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/plan-for-ip-addressing |
| Update VNet peering address space (resync) | https://learn.microsoft.com/en-us/azure/virtual-network/update-virtual-network-peering-address-space |
| Advertised gateway prefixes (summarise Azure → on-prem advertisements) | https://learn.microsoft.com/en-us/azure/virtual-network/advertised-gateway-prefixes-overview |
| VNet flow logs (NSG flow logs successor) | https://learn.microsoft.com/en-us/azure/network-watcher/vnet-flow-logs-overview |
| NSG flow logs retirement notice | https://azure.microsoft.com/updates/v2/Azure-NSG-flow-logs-Retirement |
| **v5.2, Virtual network traffic routing (route selection / LPM)** | https://learn.microsoft.com/en-us/azure/virtual-network/virtual-networks-udr-overview#how-azure-selects-routes-for-traffic-routing |
| **v5.2, AVNM user-defined route management (1,000 UDRs/table)** | https://learn.microsoft.com/en-us/azure/virtual-network-manager/concept-user-defined-route |
| Azure IPAM (open-source) | https://azure.github.io/ipam |
| ALZ policy assignments baseline | https://aka.ms/alz/policies |
| **v5.1, Gateway Load Balancer (transparent NVA insertion)** | https://learn.microsoft.com/en-us/azure/load-balancer/gateway-overview |
| **v5.1, CAF resource naming** | https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/resource-naming |
| **v5.1, CAF resource abbreviations** | https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/resource-abbreviations |
| **v5.1, Azure subscription & service limits** | https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/azure-subscription-service-limits |

---

**End of Document**
