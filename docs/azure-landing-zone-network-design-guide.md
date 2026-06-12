# Azure Landing Zone Network Design Guide v1.1

## Document Control
- Version: v1.1 — adds the route-specificity rule (deep-scan fix F1) and chain-mechanism guidance (F2); see the IP Plan v5.2 §19.7 changelog
- Status: Final Design Guide
- Date: 2026-06-12
- Audience: Cloud platform architects, network engineers, security architects
- Scope: Azure Landing Zone networking design with focus on hub/spoke IP ranges, route tables, and NSGs

## 1. Purpose
This guide provides a practical, implementation-ready blueprint for designing Azure Landing Zone networking effectively and efficiently. It aligns architecture choices, IP planning, route tables, and NSG controls so platform teams can scale without readdressing or routing rework.

This guide is designed to complement detailed IP plans (such as your v4.x documents) by defining the core standard and operating model.

## 2. Source Alignment (Microsoft Learn)
This guide is aligned to the following Microsoft guidance:
- https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/
- https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/design-principles
- https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/design-area/network-topology-and-connectivity
- https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/define-an-azure-network-topology
- https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/traditional-azure-networking-topology
- https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/plan-for-ip-addressing

## 3. Design Principles Applied
1. Subscription and network boundaries are intentional and policy-driven.
2. Network topology is chosen by scale and transit needs, not by habit.
3. IP spaces are allocated centrally and non-overlapping from day one.
4. Routing is deterministic and inspection-aware.
5. NSGs implement segmentation and least privilege, not broad allow lists.
6. Network policy, IP allocation, and deployment are automated via IaC and IPAM APIs.

## 4. Topology Decision Standard

### 4.1 Use Traditional Hub-and-Spoke when
- You need granular manual control over UDRs and inspection paths.
- You have one or a few regions and limited cross-region transit.
- Branch/site connectivity is limited and manageable.
- You rely on centralized NVAs or Azure Firewall with explicit route control.

### 4.2 Use Virtual WAN when
- You need global transit at scale across many regions.
- You require large branch integration and simplified operations.
- You need managed transitive routing between VPN and ExpressRoute scenarios.
- You want lower operational overhead than maintaining many peerings and UDR sets.

## 5. Management Group Networking Intent
- Connectivity MG: Hosts hub networking services (gateways, firewall, DNS private resolver, shared routing services).
- Corp MG: Internal/private workloads that require controlled hybrid routing.
- Online MG: Public-facing workloads isolated from Corp blast radius, with controlled communication back to internal services.

This separation is mandatory for policy clarity and reduced attack surface.

## 6. IP Address Planning Standard

### 6.1 Non-Negotiable Rules
1. Use RFC1918 address space for private Azure VNets.
2. Never allow overlap between on-prem, Azure regions, and landing zones.
3. Reserve growth blocks per region and per workload class.
4. Account for Azure subnet reservation of 5 IPs in every subnet.
5. Avoid over-allocating large VNets without evidence-based need.
6. Maintain a central IPAM source of truth with API integration.

### 6.2 Address Exclusions
Do not use these ranges in private network designs:
- 224.0.0.0/4
- 255.255.255.255/32
- 127.0.0.0/8
- 169.254.0.0/16
- 168.63.129.16/32

### 6.3 Regional Allocation Model (Recommended)
1. Enterprise allocates a global Azure supernet (example: 10.0.0.0/12).
2. Split supernet into regional blocks (example: /14 per region).
3. Inside each region:
- 1 hub block (platform connectivity services).
- 1 platform shared services block.
- 1 management block.
- 1 or more spoke pools by size class.
- 1 explicit reserved growth block.

### 6.4 Spoke Sizing Catalog (T-shirt)
- Small: /24 (256 total addresses)
- Medium: /22 (1024 total addresses)
- Large: /20 (4096 total addresses)

Use this catalog in subscription vending and landing zone provisioning workflows.

## 7. Reference CIDR Blueprint (Example)
This is a sample blueprint that can be adapted to your approved enterprise ranges.

### 7.1 Enterprise and Regional Blocks
- Azure enterprise supernet: 10.0.0.0/12
- Region A platform and spokes: 10.0.0.0/14
- Region B platform and spokes: 10.4.0.0/14
- Reserved future regions: 10.8.0.0/13

### 7.2 Region A Internal Carve (Example)
- Hub connectivity VNet: 10.0.0.0/19
- Shared services VNet: 10.0.32.0/19
- Management VNet: 10.0.64.0/19
- Spoke pool (prod medium): 10.0.128.0/17
- Spoke pool (non-prod small): 10.1.0.0/16
- Reserved growth: 10.1.128.0/17

### 7.3 Hub Subnet Pattern (Example)
- GatewaySubnet: /26
- RouteServerSubnet: /26
- AzureFirewallSubnet: /26 (if used)
- AzureBastionSubnet: /26
- North-south NVA external: /24
- North-south NVA internal: /24
- East-west NVA external: /24
- East-west NVA internal: /24
- NVA management: /24
- Hub private endpoints: /24

Note: Keep dedicated subnets for managed services that require them.

## 8. Route Table Design Standard

### 8.1 Routing Intent Model
Define routes by traffic class, not by ad-hoc prefixes:
1. Internet egress path
2. East-west inter-spoke path
3. On-prem path (ExpressRoute/VPN)
4. Platform services path
5. Cross-region path

### 8.2 Baseline Route Tables
- RT-Spoke-Workloads:
  - 0.0.0.0/0 -> Hub security egress next hop (firewall or NVA ILB)
  - Hub VNet prefixes (EXACT match per declared prefix) -> Hub east-west next hop
  - On-prem supernet(s) -> Hub east-west/connected routing next hop
- RT-Platform-Workloads and RT-GatewaySubnet:
  - One route PER SPOKE with the spoke VNet's exact prefix -> Hub inspection next hop
  - Only where explicitly required and validated; avoid unnecessary custom routes

### 8.2.1 Route-specificity rule (v1.1 — mandatory)
Azure selects routes by longest-prefix-match across ALL route sources first; the User > BGP > System priority applies only between routes with the identical prefix. VNet peering injects one system route per remote VNet address-space prefix. Therefore a UDR that must override reachability to a peered VNet MUST use a prefix exactly equal to (or more specific than) the peered VNet's prefix — summary routes (e.g., a /14 covering all spokes, or a /16 covering a hub that declares /19s) silently lose and traffic bypasses inspection. Budget UDRs accordingly: 400 per route table by default, 1,000 with AVNM-managed route tables. Reference: https://learn.microsoft.com/en-us/azure/virtual-network/virtual-networks-udr-overview#how-azure-selects-routes-for-traffic-routing

### 8.2.2 NVA chaining rule (v1.1)
Azure forwards on destination IP against the subnet's effective routes; guest-OS next hops toward another appliance in the same subnet are not honored. Chain multiple inline appliance groups only via (a) per-group subnets with per-subnet UDR cascades, (b) Gateway Load Balancer for public/North-South insertion, or (c) vendor overlay tunnels — never via same-subnet OS routing. Keep chains at 2-3 elements.

### 8.3 BGP Propagation Rules
1. Use BGP propagation carefully where gateway-learned routes are desired.
2. Disable BGP propagation on spoke route tables when learned routes bypass required inspection.
3. Validate effective routes after every change.

### 8.4 Transit Rules
- VNet peering is non-transitive by design.
- Transit must be implemented intentionally via UDR + NVA/Firewall, Route Server, or Virtual WAN.
- If VPN-to-ExpressRoute transitivity is required in hub-and-spoke, Route Server is typically required.

## 9. NSG Design Standard

### 9.1 NSG Layering Strategy
1. Subnet NSGs enforce coarse segmentation and shared controls.
2. Workload-specific NSGs enforce app-tier policy.
3. Default deny inbound and tightly scoped outbound allows.
4. Minimize broad Any-Any rules and temporary exceptions.

### 9.2 Baseline NSG Patterns by Zone
- Hub gateway subnets: Follow Azure service restrictions where NSGs are unsupported or constrained.
- NVA subnets: Allow only required health, management, and transit flows.
- Spoke web tier: Allow only ingress from approved front door/app gateway/WAF paths.
- Spoke app tier: Allow from web tier and platform dependencies only.
- Spoke data tier: Allow from app tier only; deny direct internet paths.
- Private endpoint subnets: Explicitly allow required private service traffic and deny lateral access.

### 9.3 Corp and Online Segmentation Rules
- Corp workloads: Internal access patterns, hybrid dependencies, no direct public exposure by default.
- Online workloads: Public exposure only through approved ingress services, restricted reach-back to Corp.

## 10. Inspection and Symmetry Requirements
1. Ensure flow symmetry for stateful inspection devices.
2. Keep request and response traffic through the same security path where required by NVA design.
3. Standardize ILB/backend pool design for NVA HA and predictability.
4. Validate that UDRs and peering flags support forwarded traffic behavior.

## 11. DNS and Private Endpoint Considerations
1. Use Azure Private DNS and Private Resolver with dedicated delegated subnets where applicable.
2. If using private endpoint network policies, validate route/NSG behavior intentionally.
3. Ensure DNS forwarding paths are allowed through inspection devices.
4. Avoid wildcard forwarding patterns that conflict with gateway or resolver constraints.

## 12. IPv6 Guidance
1. Adopt dual-stack where business or scale requires it.
2. Keep IPv4 and IPv6 rule sets aligned in NSGs and route controls.
3. Use required IPv6 subnet sizing (/64).
4. Use staged adoption to reduce migration risk.

## 13. Scale and Limits Checklist
Validate these limits during design and quarterly review:
- VNet peering limits per VNet
- ExpressRoute route advertisement limits
- Gateway throughput and tunnel limits
- Firewall/NVA throughput and connection scale
- Route table and NSG rule scale limits

## 14. Validation and Operational Runbook

### 14.1 Pre-Deployment Validation
1. IPAM overlap checks pass for all planned prefixes.
2. Route intent documented for each subnet category.
3. NSG rules reviewed for least privilege and shadowed rules.
4. Platform policy assignments validated for connectivity, Corp, and Online scopes.

### 14.2 Post-Deployment Validation
1. Validate effective routes for representative spoke subnets.
2. Validate effective NSG rules for representative NICs/subnets.
3. Run connectivity tests for:
- Spoke to internet egress
- Spoke to on-prem
- Spoke to shared platform services
- Spoke to spoke (approved paths only)
4. Verify inspection logs for expected traffic classes.

### 14.3 Change Management
1. Any CIDR change requires impact analysis and peering/route resync plan.
2. Any route change requires inspection-path validation.
3. Any NSG exception requires expiry date and owner.
4. Decommissioned workloads must release address space in IPAM.

## 15. Implementation Templates

### 15.1 Route Table Template (Logical)
- Name: RT-<zone>-<purpose>
- Association: <subnet list>
- Routes:
  - Default route: 0.0.0.0/0 -> <hub security next hop>
  - On-prem summary: <corp ranges> -> <hub transit next hop>
  - Optional regional summary: <region summary> -> <inspection next hop>
- BGP propagation: Enabled or disabled per inspected-routing policy

### 15.2 NSG Template (Logical)
- Name: NSG-<zone>-<tier>
- Inbound:
  - Allow from approved source groups only
  - Deny all remaining inbound
- Outbound:
  - Allow to approved dependencies only
  - Deny direct lateral or internet where not required
- Governance:
  - Rule naming convention
  - Rule owner tag
  - Expiry tag for temporary exceptions

## 16. Golden Rules for Effective and Efficient Design
1. Never allocate a spoke before IPAM reservation is complete.
2. Never deploy a route table without a documented traffic intent.
3. Never allow broad NSG exceptions without owner and expiry.
4. Never trust transitivity assumptions in Azure peering.
5. Never mix Corp and Online traffic domains without explicit controls.
6. Always reserve future space before it is urgently needed.
7. Always validate effective routes and NSG behavior after every network change.
8. Never expect a summary UDR to override a more-specific peering system route — steering routes must match the peered VNet prefix exactly (see 8.2.1).
9. Never design NVA-to-NVA forwarding inside one subnet — Azure routes by destination via effective routes only (see 8.2.2).

## 17. Final Recommendation
For most enterprises starting or standardizing landing zones:
1. Begin with traditional regional hub-and-spoke using strict IPAM and standardized UDR/NSG patterns.
2. Add global transit with Virtual WAN when scale and operational complexity justify the transition.
3. Keep design artifacts versioned and enforce them through policy plus IaC pipelines.

This approach gives strong control now while preserving a clean path to global scale later.
