// SPDX-License-Identifier: Apache-2.0
// #71 — the SHARED Node-side SSRF resolution guard. `isPublicDnsShard` (index.mjs) is the PORTABLE lexical floor
// (all a browser can do); it cannot catch a syntactically-public NAME that RESOLVES to an internal ADDRESS
// (127.0.0.1, 10/8, 169.254/16, ::1, fc00::/7 …). This module resolves the host and refuses the fetch if ANY
// A/AAAA record is private/loopback/link-local — BEFORE any connection. It is a Node-ONLY OPT-IN subpath
// (`ust-protocol/ssrf`), never imported by the zero-dep/browser core; the MCP and CLI both pass its wrapper as
// the `fetchImpl` to resolveByDiscovery, so every auto-fetching Node surface shares one guard (audit: MCP-only → all).
//
// Bounded residual (documented): resolves-then-fetches without pinning the exact socket, so a DNS-rebind flip
// between the check and the connection is not closed here (that needs a pinning dispatcher). Impact is already
// bounded — the fetched genesis/key-log is content-addressed + signature-checked, so SSRF here is an internal
// reachability probe, never an identity forgery.
import { promises as dns } from 'node:dns';
import net from 'node:net';

// round-51 — the IANA IPv6 Special-Purpose Address Registry, globally_reachable=false, as DATA (prefix bytes, prefix bits).
// EMBED-IPv4 forms (::ffff:0:0/96, 64:ff9b::/96, 2002::/16, ::/96) are handled separately (classify the embedded octets); this
// is the "refuse outright" set. fc00::/7, fe80::/10, ff00::/8 stay inline (bitmask). A new IANA allocation is one ROW here.
const V6_SPECIAL = [
  [[0, 0x64, 0xff, 0x9b, 0, 1], 48],          // 64:ff9b:1::/48 IPv4/IPv6 translation, local-use (RFC 8215)
  [[0x20, 0x01, 0, 2, 0, 0], 48],             // 2001:2::/48 Benchmarking (RFC 5180)
  [[0x20, 0x01, 0, 0x10], 28],                // 2001:10::/28 ORCHID, deprecated (RFC 4843)
  [[0x20, 0x01, 0x0d, 0xb8], 32],             // 2001:db8::/32 Documentation (RFC 3849)
  [[0x3f, 0xff], 20],                         // 3fff::/20 Documentation (RFC 9637)
  [[0x5f, 0x00], 16],                         // 5f00::/16 Segment Routing (SRv6) SIDs (RFC 9602)
  [[1, 0, 0, 0, 0, 0, 0, 0], 64],             // 100::/64 Discard-Only (RFC 6666)
];
export function isPrivateIp(ip) {
  const v = net.isIP(ip);
  if (v === 4) {
    const o = ip.split('.').map(Number);
    if (o.length !== 4 || o.some((n) => !(n >= 0 && n <= 255))) return true;   // malformed → refuse
    // round-51 P1-01 (owner: complete registry, not a hand list) — the IANA IPv4 Special-Purpose Address Registry: every
    // globally_reachable=false range + non-unicast blocks. A hand subset kept missing rows (198.18/15 benchmark, 192.0.2/24 &
    // 198.51.100/24 & 203.0.113/24 doc, 192.88.99/24 deprecated 6to4 relay — round-51). This is the whole table, prefix-matched.
    const p4 = (a, b, c, d, bits) => { const w = [a, b, c, d], nb = bits >> 3, r = bits & 7; for (let i = 0; i < nb; i++) if (o[i] !== w[i]) return false; return !r || !(((o[nb] ^ w[nb]) & (0xff << (8 - r)))); };
    return p4(0, 0, 0, 0, 8) || p4(10, 0, 0, 0, 8) || p4(100, 64, 0, 0, 10) || p4(127, 0, 0, 0, 8) || p4(169, 254, 0, 0, 16)
      || p4(172, 16, 0, 0, 12) || p4(192, 0, 0, 0, 24) || p4(192, 0, 2, 0, 24) || p4(192, 88, 99, 0, 24) || p4(192, 168, 0, 0, 16)
      || p4(198, 18, 0, 0, 15) || p4(198, 51, 100, 0, 24) || p4(203, 0, 113, 0, 24) || o[0] >= 224;   // 224/4 multicast + 240/4 reserved + 255.255.255.255 broadcast
  }
  if (v === 6) {
    // round-49/50 P1-01 — classify by BYTE RANGE from a special-use PREFIX TABLE (IANA IPv6 Special-Purpose registry subset), not
    // a short hand list: a hand list missed the hex form ::ffff:7f00:1 (round-49) AND the local-use NAT64 64:ff9b:1::/48 (round-50).
    // A prefix that EMBEDS an IPv4 is classified via the v4 policy; every other non-globally-reachable prefix is refused outright.
    const b = ipv6ToBytes(ip.toLowerCase().split('%')[0]);
    if (!b) return true;                                                        // unparseable (net.isIP said v6, but be safe) → refuse
    const pfx = (p, bits) => { const nb = bits >> 3, r = bits & 7; for (let i = 0; i < nb; i++) if (b[i] !== p[i]) return false; return !r || !(((b[nb] ^ p[nb]) & (0xff << (8 - r)))); };
    // (1) forms that EMBED an IPv4 → classify the embedded octets via the v4 policy (ANY spelling)
    if (pfx([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff], 96)) return isPrivateIp(b.slice(12).join('.'));     // ::ffff:0:0/96 IPv4-mapped
    if (pfx([0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0], 96)) return isPrivateIp(b.slice(12).join('.'));  // 64:ff9b::/96 NAT64 well-known
    if (pfx([0x20, 0x02], 16)) return isPrivateIp(b.slice(2, 6).join('.'));                                 // 2002::/16 6to4 → embedded relay IPv4 (bytes 2..5)
    if (b.slice(0, 12).every((x) => x === 0)) return isPrivateIp(b.slice(12).join('.'));                    // ::/96 IPv4-compatible — covers ::1 loopback + :: unspecified (→ 0.0.0.x, private)
    // (2) every OTHER non-globally-reachable special-use prefix → refuse. round-51 (owner: IPv6 as complete as IPv4) — the whole
    // IANA IPv6 Special-Purpose Address Registry (globally_reachable=false) as a data TABLE, not a hand list: a new allocation is a
    // ROW. A hand list had leaked 2001:2::/48 (benchmarking) + 2001:10::/28 (ORCHID). The v6 registry-completeness test pins it.
    return (b[0] & 0xfe) === 0xfc                        // fc00::/7 unique-local
      || (b[0] === 0xfe && (b[1] & 0xc0) === 0x80)       // fe80::/10 link-local
      || b[0] === 0xff                                   // ff00::/8 multicast (never a unicast fetch target)
      || V6_SPECIAL.some(([p, bits]) => pfx(p, bits));
  }
  return true;                                                                  // not an IP literal → caller resolves
}

// Parse a lower-cased IPv6 literal to its 16 octets (handles `::` compression + an embedded IPv4 tail `::ffff:1.2.3.4` /
// `::1.2.3.4`). round-49 P1-01 — the mapped range must be caught in EVERY spelling, so classification runs over bytes, not text.
function ipv6ToBytes(a) {
  let s = a, v4 = null;
  const li = s.lastIndexOf(':');
  if (li >= 0 && s.slice(li + 1).includes('.')) {                              // embedded dotted IPv4 tail
    const parts = s.slice(li + 1).split('.');
    if (parts.length !== 4 || parts.some((p) => !/^\d{1,3}$/.test(p) || Number(p) > 255)) return null;
    v4 = parts.map(Number); s = s.slice(0, li + 1);                            // keep the trailing ':' before the tail
  }
  const dbl = s.split('::');
  if (dbl.length > 2) return null;
  const lh = dbl[0] ? dbl[0].split(':').filter(Boolean) : [];
  const rh = dbl.length === 2 ? (dbl[1] ? dbl[1].split(':').filter(Boolean) : []) : null;
  const need = 8 - (v4 ? 2 : 0);
  const hextets = rh === null ? lh : [...lh, ...Array(need - lh.length - rh.length).fill('0'), ...rh];
  if (rh === null ? hextets.length !== need : (need - lh.length - rh.length) < 0) return null;
  const bytes = [];
  for (const h of hextets) { if (!/^[0-9a-f]{1,4}$/.test(h)) return null; const n = parseInt(h, 16); bytes.push((n >> 8) & 0xff, n & 0xff); }
  if (v4) bytes.push(...v4);
  return bytes.length === 16 ? bytes : null;
}

// Wrap a fetch so a discovery target that resolves to a private address is refused before connecting.
export function makeSsrfSafeFetch(baseFetch = fetch, { resolver = dns.lookup } = {}) {
  return async function ssrfSafeFetch(url, opts) {
    let host;
    try { host = new URL(String(url)).hostname; } catch { throw new Error('SSRF guard: unparseable URL'); }
    const bracketless = host.replace(/^\[|\]$/g, '');
    if (net.isIP(bracketless) !== 0) {
      if (isPrivateIp(bracketless)) throw new Error('SSRF guard: refusing private IP literal ' + bracketless);
    } else {
      let addrs;
      try { addrs = await resolver(host, { all: true }); } catch { throw new Error('SSRF guard: cannot resolve ' + host); }
      const list = Array.isArray(addrs) ? addrs : [{ address: addrs }];
      for (const a of list) if (isPrivateIp(a.address)) throw new Error('SSRF guard: ' + host + ' resolves to private ' + a.address);
    }
    return baseFetch(url, opts);
  };
}
