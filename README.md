# AzIP-Ranger — Azure Landing Zone Network Designer

> **Interactive Hub & Spoke IP Planning, Routing, and Security Catalogs**
>
> ⚡ *100% client-side, zero server dependencies, runs entirely in your browser.*

[![Aesthetics](https://img.shields.io/badge/Aesthetics-Modern-blueviolet)](#)
[![Tech Stack](https://img.shields.io/badge/Tech--Stack-Vanilla%20JS%20%2F%20CSS-blue)](#)
[![Deployment](https://img.shields.io/badge/Deployment-GitHub%20Pages-success)](#)

---

**AzIP-Ranger** is a free, lightweight helper tool to plan your Azure Landing Zone IP ranges. It is designed to be used completely as-is. The utility turns a few structured inputs into a complete, validated Azure landing zone network architecture, automating Microsoft Cloud Adoption Framework (CAF) guidelines for IP addressing, routing tables, and security boundaries.

## 🚀 Key Features

* **Flexible Architectures**: Choose from dual-tier NVA (North-South & East-West), single-tier NVA, Azure Firewall-only, or direct routing. You can also chain Azure Firewall right into your NVA setup.
* **Auto-Assigned IPs**: The engine handles all the tricky VIP layouts (`.100`, `.101`, etc.) and static NIC assignments (`.4` to `.99`) for HA clusters and VMSS.
* **Spoke Sizing**: Use standard `S` (`/24`), `M` (`/22`), or `L` (`/20`) sizes, or switch to "Auto Right-Size" mode to pack spokes as tightly as possible.
* **CAF Naming**: Generates consistent resource names using official prefixes like `vnet-`, `snet-`, `nsg-`, `rt-`, `nva-`, and `vmss-`.
* **Visual Topology**: See your design live with an interactive SVG diagram that shows traffic flow, routing paths, and spoke details.
* **Export Options**: Save your work as JSON, download a Markdown report, or grab CSVs for subnets, route tables, and NSG rules.

## 📂 Project Structure

```text
IP Ranges for Azure Landing Zone/
├── index.html        # Main application UI and structure
├── README.md         # Project documentation (this file)
├── LICENSE           # MIT License terms
├── .nojekyll         # Disables Jekyll processing on GitHub Pages
├── css/
│   └── styles.css    # Premium, responsive theme styles (light/dark)
├── js/
│   ├── app.js        # DOM event binding & UI state coordination
│   ├── engine.js     # IP range allocation and rule verification
│   ├── cidr.js       # IPv4 CIDR math and subnet arithmetic
│   └── config.js     # Default regions, environments, and dropdown values
└── docs/
    ├── azure-landing-zone-ip-plan.md             # Core architecture reference
    └── azure-landing-zone-network-design-guide.md # General design constraints
```

## 🛠️ Getting Started & Usage

### Running Locally
Since AzIP-Ranger is completely serverless and static, simply open `index.html` in any web browser to run the application.

### Configuration
You can customize standard regions, environments, spoke sizes, and VM counts by editing [js/config.js](file:///c:/temp/IP%20Ranges%20for%20Azure%20Landing%20Zone/js/config.js). The UI and calculation engines will automatically adapt to your changes.

> 💡 **Tip:** When releasing changes, bump the version query strings (`?v=2.6.1` -> `?v=X.Y.Z`) on script and link tags in `index.html` to prevent browser cache issues.

## 📖 Architecture Documentation
For details on the specifications and constraints driving the engine:
* [Azure Landing Zone IP Plan](docs/azure-landing-zone-ip-plan.md) — Reference architecture
* [Network Design Guide](docs/azure-landing-zone-network-design-guide.md) — Landing zone connectivity guidelines.

## ⚖️ License & Disclaimer

This tool is free to use and released under the **MIT License**.

> ⚠️ **Disclaimer:** This is not an official product. This is a personal tool I created in my free time for experimenting. It is provided "as-is" without warranty of any kind. Always validate your final network designs against your organization's specific requirements and live Microsoft documentation before deploying.
