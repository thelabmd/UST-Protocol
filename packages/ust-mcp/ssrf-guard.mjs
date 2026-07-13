// SPDX-License-Identifier: Apache-2.0
// #69 E4 — Node-side SSRF resolution guard for the MCP (the primary UNTRUSTED-input surface: an agent hands
// the server a document and it auto-fetches that document's domain_shard). ust-protocol's isPublicDnsShard is
// the portable LEXICAL floor (all a browser can do); it cannot catch a syntactically-public name that RESOLVES
// to an internal address (127.0.0.1, 10/8, 169.254/16, ::1, fc00::/7 …). This wrapper resolves the host and
// refuses the fetch if ANY A/AAAA record is private/loopback/link-local — BEFORE any connection is made.
//
// Bounded residual (documented, not hidden): this resolves-then-fetches without pinning the exact socket, so a
// DNS-rebind flip between the check and the connection is not closed here (that needs a pinning dispatcher).
// The impact is already bounded — the fetched genesis/key-log is content-addressed and signature-checked, so
// SSRF here is an internal-reachability probe, never an identity forgery. Use as a fetchImpl for resolveByDiscovery.
import { promises as dns } from 'node:dns';
import net from 'node:net';

// Classify an IP literal as private/loopback/link-local/reserved (→ refuse) vs public.
export function isPrivateIp(ip) {
  const v = net.isIP(ip);
  if (v === 4) {
    const o = ip.split('.').map(Number);
    if (o.length !== 4 || o.some((n) => !(n >= 0 && n <= 255))) return true;   // malformed → refuse
    return (
      o[0] === 0 || o[0] === 10 || o[0] === 127 ||                              // 0/8, 10/8, loopback
      (o[0] === 100 && o[1] >= 64 && o[1] <= 127) ||                            // 100.64/10 CGNAT
      (o[0] === 169 && o[1] === 254) ||                                         // link-local
      (o[0] === 172 && o[1] >= 16 && o[1] <= 31) ||                             // 172.16/12
      (o[0] === 192 && o[1] === 168) ||                                         // 192.168/16
      (o[0] === 192 && o[1] === 0 && o[2] === 0) ||                             // 192.0.0/24
      o[0] >= 224                                                              // multicast/reserved 224+
    );
  }
  if (v === 6) {
    let a = ip.toLowerCase().split('%')[0];
    if (a === '::1' || a === '::') return true;                                 // loopback / unspecified
    const m = a.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);                         // IPv4-mapped → classify as v4
    if (m) return isPrivateIp(m[1]);
    return a.startsWith('fc') || a.startsWith('fd') ||                          // fc00::/7 unique-local
      a.startsWith('fe8') || a.startsWith('fe9') || a.startsWith('fea') || a.startsWith('feb'); // fe80::/10 link-local
  }
  return true;                                                                  // not an IP literal → caller resolves
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
