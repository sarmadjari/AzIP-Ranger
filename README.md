# AzIP-Ranger: Azure Landing Zone Network Designer

> **Interactive Hub & Spoke IP Planning, Routing, and Security Catalogs**
>
> ⚡ *100% client-side, zero server dependencies, runs entirely in your browser.*

[![Aesthetics](https://img.shields.io/badge/Aesthetics-Modern-blueviolet)](#)
[![Tech Stack](https://img.shields.io/badge/Tech--Stack-Vanilla%20JS%20%2F%20CSS-blue)](#)
[![Deployment](https://img.shields.io/badge/Deployment-GitHub%20Pages-success)](#)

---

**AzIP-Ranger** is a free, lightweight helper tool to plan your Azure Landing Zone IP ranges. It is designed to be used completely as-is. The utility turns a few structured inputs into a complete, validated Azure landing zone network architecture, automating Microsoft Cloud Adoption Framework (CAF) guidelines for IP addressing, routing tables, and security boundaries.
> **Live demo:** https://sarmadjari.github.io/AzIP-Ranger/

## 🚀 Key Features

* **Flexible Architectures**: Choose from dual-tier NVA (North-South & East-West), single-tier NVA, Azure Firewall-only, or direct routing. You can also chain Azure Firewall right into your NVA setup.
* **Auto-Assigned IPs**: The engine handles all the tricky VIP layouts (`.100`, `.101`, etc.) and static NIC assignments (`.4` to `.99`) for HA clusters and VMSS.
* **Spoke Sizing**: Use standard `S` (`/24`), `M` (`/22`), or `L` (`/20`) sizes, or switch to "Auto Right-Size" mode to pack spokes as tightly as possible.
* **CAF Naming**: Generates consistent resource names using official prefixes like `vnet-`, `snet-`, `nsg-`, `rt-`, `nva-`, and `vmss-`.
* **Visual Topology**: See your design live with an interactive SVG diagram that shows traffic flow, routing paths, and spoke details.
* **Export Options**: Save your work as JSON, download a Markdown report, or grab CSVs for subnets, route tables, and NSG rules.

## 📂 Project Structure

```text
AzIP-Ranger/
├── index.html        # Main application UI (header badge shows engine + plan version)
├── README.md         # Project documentation (this file)
├── LICENSE           # MIT License terms
├── .nojekyll         # Disables Jekyll processing on GitHub Pages
├── css/
│   └── styles.css    # Premium, responsive theme styles (light/dark)
├── js/
│   ├── version.js    # SINGLE SOURCE OF TRUTH for versions (app, IP plan, guide, links)
│   ├── app.js        # DOM event binding & UI state coordination
│   ├── engine.js     # IP allocation, routing/NSG generation, rule verification
│   ├── export.js     # Markdown / CSV / JSON serializers
│   ├── cidr.js       # IPv4 CIDR math and subnet arithmetic
│   └── config.js     # Default regions, environments, and dropdown values
└── docs/
    ├── why-azip-ranger.md                         # Plain-language value companion (start here)
    ├── azure-landing-zone-ip-plan.md              # Core architecture reference (v5.2)
    ├── azure-landing-zone-network-design-guide.md # Design principles & golden rules (v1.2)
    └── highly-available-nvas.md                   # HA NVA patterns & symmetry deep-dive (v1.0)
```

## 🛠️ Getting Started & Usage

### Running Locally
Since AzIP-Ranger is completely serverless and static, simply open `index.html` in any web browser to run the application.



## 📖 Architecture Documentation
For details on the specifications and constraints driving the engine:
* [Why AzIP-Ranger](docs/why-azip-ranger.md), what the project is good at and what it helps with (start here)
* [Azure Landing Zone IP Plan](docs/azure-landing-zone-ip-plan.md), Reference architecture (NVA arm concept in Section 6.1.1)
* [Network Design Guide](docs/azure-landing-zone-network-design-guide.md), Landing zone connectivity guidelines and golden rules.
* [Highly Available NVAs](docs/highly-available-nvas.md), HA NVA patterns, traffic symmetry, and when to use Azure Firewall.

## ⚖️ License & Disclaimer

This tool is free to use and released under the **MIT License**.

> ⚠️ **Disclaimer:** This is not an official product. This is a personal tool I created in my free time for experimenting. It is provided "as-is" without warranty of any kind. Always validate your final network designs against your organization's specific requirements and live Microsoft documentation before deploying.
