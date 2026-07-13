// #69 E4 — the resolution guard refuses a public NAME that resolves to a private ADDRESS (what the lexical
// floor cannot catch), and private IP literals directly.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isPrivateIp, makeSsrfSafeFetch } from './ssrf-guard.mjs';

test('isPrivateIp classifies v4 ranges', () => {
  for (const ip of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '224.0.0.1'])
    assert.equal(isPrivateIp(ip), true, ip + ' should be private');
  for (const ip of ['8.8.8.8', '1.1.1.1', '172.15.0.1', '172.32.0.1', '93.184.216.34'])
    assert.equal(isPrivateIp(ip), false, ip + ' should be public');
});

test('isPrivateIp classifies v6 ranges', () => {
  for (const ip of ['::1', '::', 'fc00::1', 'fd12:3456::1', 'fe80::1', '::ffff:127.0.0.1', '::ffff:10.0.0.1'])
    assert.equal(isPrivateIp(ip), true, ip + ' should be private');
  for (const ip of ['2606:4700:4700::1111', '2001:4860:4860::8888', '::ffff:8.8.8.8'])
    assert.equal(isPrivateIp(ip), false, ip + ' should be public');
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
