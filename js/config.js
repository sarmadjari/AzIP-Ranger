/* ═══════════════════════════════════════════════════════════════
   AzIP-Ranger · config.js — edit the lists here, the app picks
   them up everywhere (dropdowns, naming convention, IP sizing).

   Each entry is { name, value }:
     name  = what the user sees
     value = what goes into generated names / calculations

   Spoke sizes also carry `prefix` (the CIDR size). S/M/L map to
   the v5.0 reference pools; any other prefix works in Auto mode.
   ═══════════════════════════════════════════════════════════════ */
(function (root) {
  "use strict";
  root.AZIP_CONFIG = {

    defaults: {
      region: "westeurope",
      environment: "prod",
    },

    /* Azure regions — value is used verbatim in every generated name */
    regions: [
      { name: "West Europe",          value: "westeurope" },
      { name: "North Europe",         value: "northeurope" },
      { name: "UK South",             value: "uksouth" },
      { name: "Sweden Central",       value: "swedencentral" },
      { name: "Germany West Central", value: "germanywestcentral" },
      { name: "France Central",       value: "francecentral" },
      { name: "Switzerland North",    value: "switzerlandnorth" },
      { name: "East US",              value: "eastus" },
      { name: "East US 2",            value: "eastus2" },
      { name: "Central US",           value: "centralus" },
      { name: "West US 3",            value: "westus3" },
      { name: "Canada Central",       value: "canadacentral" },
      { name: "Brazil South",         value: "brazilsouth" },
      { name: "UAE North",            value: "uaenorth" },
      { name: "Qatar Central",        value: "qatarcentral" },
      { name: "South Africa North",   value: "southafricanorth" },
      { name: "Southeast Asia",       value: "southeastasia" },
      { name: "Japan East",           value: "japaneast" },
      { name: "Korea Central",        value: "koreacentral" },
      { name: "Central India",        value: "centralindia" },
      { name: "Australia East",       value: "australiaeast" },
    ],

    /* Spoke environments — value flows into vnet-/snet-/nsg-/rt- names */
    environments: [
      { name: "Production",  value: "prod" },
      { name: "Development", value: "dev" },
      { name: "Test",        value: "test" },
      { name: "UAT",         value: "uat" },
      { name: "QA",          value: "qa" },
      { name: "Staging",     value: "staging" },
      { name: "Sandbox",     value: "sandbox" },
      { name: "DR",          value: "dr" },
    ],

    /* Spoke VNet T-shirt sizes — S/M/L use the v5.0 reference pools;
       additional prefixes are allocated in Auto (right-size) mode    */
    spokeSizes: [
      { name: "S /24 — 256 IPs",   value: "S", prefix: 24 },
      { name: "M /22 — 1,024 IPs", value: "M", prefix: 22 },
      { name: "L /20 — 4,096 IPs", value: "L", prefix: 20 },
    ],

    /* Allowed VM counts per NVA tier — anything beyond this list
       should be a VMSS with autoscale                              */
    nvaVmCounts: [1, 2, 3],
  };
}(typeof self !== "undefined" ? self : this));
