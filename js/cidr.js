/* ═══════════════════════════════════════════════════════════════
   cidr.js, pure IPv4/CIDR math (no DOM). Used by engine.js and
   by the Node unit tests. All addresses handled as unsigned ints.
   ═══════════════════════════════════════════════════════════════ */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.LZ_CIDR = factory();
}(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const U32 = 0x100000000; // 2^32

  function ipToInt(str) {
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(str).trim());
    if (!m) return null;
    let n = 0;
    for (let i = 1; i <= 4; i++) {
      const o = Number(m[i]);
      if (o > 255) return null;
      n = n * 256 + o;
    }
    return n;
  }

  function intToIp(n) {
    n = n >>> 0 === n ? n : Math.floor(n) % U32;
    return [(n / 16777216) | 0, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
  }

  function sizeOf(prefix) { return Math.pow(2, 32 - prefix); }

  /** Parse "a.b.c.d/p". Returns {ok, base, prefix, size, exact, input, error} */
  function parseCidr(str) {
    const s = String(str || "").trim();
    const m = /^([\d.]+)\s*\/\s*(\d{1,2})$/.exec(s);
    if (!m) return { ok: false, error: "Use CIDR notation, e.g. 10.0.0.0/12" };
    const ip = ipToInt(m[1]);
    const prefix = Number(m[2]);
    if (ip === null) return { ok: false, error: "Invalid IPv4 address" };
    if (prefix < 1 || prefix > 32) return { ok: false, error: "Prefix must be /1–/32" };
    const size = sizeOf(prefix);
    const base = Math.floor(ip / size) * size;
    return { ok: true, base, prefix, size, exact: base === ip, input: s,
             normalized: intToIp(base) + "/" + prefix };
  }

  function cidr(base, prefix) { return intToIp(base) + "/" + prefix; }

  function lastAddr(base, prefix) { return base + sizeOf(prefix) - 1; }

  function contains(aBase, aPrefix, bBase, bPrefix) {
    return bPrefix >= aPrefix &&
           Math.floor(bBase / sizeOf(aPrefix)) * sizeOf(aPrefix) === aBase;
  }

  function overlaps(aBase, aPrefix, bBase, bPrefix) {
    return aBase <= lastAddr(bBase, bPrefix) && bBase <= lastAddr(aBase, aPrefix);
  }

  /** Align addr up to the next boundary of the given prefix length. */
  function alignUp(addr, prefix) {
    const size = sizeOf(prefix);
    return Math.ceil(addr / size) * size;
  }

  /** Smallest prefix length whose block size >= n addresses. */
  function prefixForSize(n) {
    let p = 32;
    while (p > 0 && sizeOf(p) < n) p--;
    return p;
  }

  /** Smallest single CIDR block, starting at or after `start`, aligned, covering [start, end). */
  function coveringPrefix(start, end) {
    let p = 32;
    while (p > 0) {
      const size = sizeOf(p);
      const base = Math.floor(start / size) * size;
      if (base + size >= end && base <= start) return { base, prefix: p };
      p--;
    }
    return { base: 0, prefix: 0 };
  }

  /** Azure usable hosts: total − 5 (network, 3× Azure-reserved, broadcast). */
  function usable(prefix) { return Math.max(0, sizeOf(prefix) - 5); }

  const RFC1918 = [
    { base: ipToInt("10.0.0.0"), prefix: 8 },
    { base: ipToInt("172.16.0.0"), prefix: 12 },
    { base: ipToInt("192.168.0.0"), prefix: 16 },
  ];

  /** Ranges that must never appear in a private design (see IP Plan / Design Guide). */
  const FORBIDDEN = [
    { base: ipToInt("224.0.0.0"), prefix: 4, why: "multicast (224.0.0.0/4)" },
    { base: ipToInt("255.255.255.255"), prefix: 32, why: "broadcast (255.255.255.255/32)" },
    { base: ipToInt("127.0.0.0"), prefix: 8, why: "loopback (127.0.0.0/8)" },
    { base: ipToInt("169.254.0.0"), prefix: 16, why: "link-local (169.254.0.0/16)" },
    { base: ipToInt("168.63.129.16"), prefix: 32, why: "Azure WireServer/DNS (168.63.129.16/32)" },
  ];

  function isRfc1918(base, prefix) {
    return RFC1918.some(r => contains(r.base, r.prefix, base, prefix));
  }

  function forbiddenHit(base, prefix) {
    const hit = FORBIDDEN.find(f => overlaps(f.base, f.prefix, base, prefix));
    return hit ? hit.why : null;
  }

  /**
   * Sequential aligned allocator.
   * items: [{ key, prefix, ... }], allocated in order, each aligned to its own size.
   * Returns { items: [{...item, base, cidr}], end } (end = first free address).
   */
  function allocate(start, items) {
    let cursor = start;
    const out = [];
    for (const it of items) {
      const base = alignUp(cursor, it.prefix);
      out.push(Object.assign({}, it, { base, cidr: cidr(base, it.prefix) }));
      cursor = base + sizeOf(it.prefix);
    }
    return { items: out, end: cursor };
  }

  function fmt(n) { return n.toLocaleString("en-US"); }

  return {
    ipToInt, intToIp, parseCidr, cidr, sizeOf, lastAddr, contains, overlaps,
    alignUp, prefixForSize, coveringPrefix, usable, isRfc1918, forbiddenHit,
    allocate, fmt, RFC1918, FORBIDDEN,
  };
}));
