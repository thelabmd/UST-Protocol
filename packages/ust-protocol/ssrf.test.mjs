// #69 E4 — the resolution guard refuses a public NAME that resolves to a private ADDRESS (what the lexical
// floor cannot catch), and private IP literals directly.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isPrivateIp, makeSsrfSafeFetch } from './ssrf.mjs';

test('isPrivateIp classifies v4 ranges', () => {
  for (const ip of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '224.0.0.1',
    // round-51 P1-01 — the complete IANA special-purpose registry: benchmarking + documentation + deprecated-relay + reserved:
    '198.18.0.1', '198.19.255.254', '192.0.2.1', '198.51.100.1', '203.0.113.1', '192.88.99.1', '240.0.0.1', '255.255.255.255'])
    assert.equal(isPrivateIp(ip), true, ip + ' should be private');
  for (const ip of ['8.8.8.8', '1.1.1.1', '172.15.0.1', '172.32.0.1', '93.184.216.34', '198.20.0.1', '192.0.3.1'])   // round-51 — just outside the special ranges stays public
    assert.equal(isPrivateIp(ip), false, ip + ' should be public');
});

test('isPrivateIp classifies v6 ranges', () => {
  for (const ip of ['::1', '::', 'fc00::1', 'fd12:3456::1', 'fe80::1', '::ffff:127.0.0.1', '::ffff:10.0.0.1',
    // round-49 P1-01 — the mapped range must be caught in EVERY spelling, not only dotted-decimal:
    '::ffff:7f00:1', '::ffff:0a00:1', '::ffff:a9fe:a9fe', '::ffff:169.254.169.254', '::127.0.0.1', '64:ff9b::7f00:1',
    // round-50 P1-01 — the special-use PREFIX TABLE: local-use NAT64 (64:ff9b:1::/48), 6to4-to-private, documentation, discard, multicast:
    '64:ff9b:1::7f00:1', '64:ff9b:1::a00:1', '2002:c0a8:0101::1', '2001:db8::1', '100::1', 'ff02::1',
    // round-51 — the COMPLETE IANA IPv6 Special-Purpose registry (globally_reachable=false): benchmarking + ORCHID + doc9637 + SRv6:
    '2001:2::1', '2001:2:0:ffff::1', '2001:10::1', '2001:1f::1', '3fff::1', '5f00::1'])
    assert.equal(isPrivateIp(ip), true, ip + ' should be private');
  for (const ip of ['2606:4700:4700::1111', '2001:4860:4860::8888', '::ffff:8.8.8.8', '::ffff:808:808', '2002:5db8:d877::1',
    // round-51 — the boundaries: ORCHIDv2 (2001:20::/28) is globally reachable; just-outside doc/benchmark/orchid stays public:
    '2001:20::1', '2001:db9::1', '2000::1', '3ffe::1', '2001:3::1'])
    assert.equal(isPrivateIp(ip), false, ip + ' should be public');   // round-50/51 — 6to4-public + genuinely-global special ranges stay public
});

test('public name → public IP: fetch proceeds', async () => {
  let called = false;
  const base = async () => { called = true; return { ok: true }; };
  const f = makeSsrfSafeFetch(base, { resolver: async () => [{ address: '93.184.216.34' }] });
  await f('https://example.com/.well-known/ust-genesis');
  assert.equal(called, true);
});

test('P0 #69 E4 — public name resolving to a PRIVATE address → refused, base fetch never called', async () => {
  let called = false;
  const base = async () => { called = true; return { ok: true }; };
  const f = makeSsrfSafeFetch(base, { resolver: async () => [{ address: '169.254.169.254' }] });
  await assert.rejects(() => f('https://metadata.evil.example/latest'), /SSRF guard/);
  assert.equal(called, false);
});

test('ANY private record among several → refused (no cherry-picking a public one)', async () => {
  const base = async () => ({ ok: true });
  const f = makeSsrfSafeFetch(base, { resolver: async () => [{ address: '93.184.216.34' }, { address: '127.0.0.1' }] });
  await assert.rejects(() => f('https://x.example/'), /SSRF guard/);
});

test('private IP literal (no DNS) → refused', async () => {
  const base = async () => ({ ok: true });
  const f = makeSsrfSafeFetch(base, { resolver: async () => { throw new Error('should not resolve a literal'); } });
  await assert.rejects(() => f('http://127.0.0.1:8080/'), /SSRF guard/);
  await assert.rejects(() => f('http://[::1]/'), /SSRF guard/);
});

test('unresolvable host → refused (fail-closed)', async () => {
  const base = async () => ({ ok: true });
  const f = makeSsrfSafeFetch(base, { resolver: async () => { throw new Error('ENOTFOUND'); } });
  await assert.rejects(() => f('https://nx.example/'), /cannot resolve/);
});
