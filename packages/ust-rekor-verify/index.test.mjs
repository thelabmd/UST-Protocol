// @assurance 3 canfail:yes — a REAL rekor.sigstore.dev anchor, but CAPTURED: nothing re-fetches the signed tree head,
// so the frozen fixture decides at run time. Not 1a — the bytes came from outside once and now live here.
// #69 Theme A1 regression: the anchor terminates at Rekor's SIGNED tree head, never a self-consistent
// Merkle object. Uses a captured REAL rekor.sigstore.dev anchor (noosphere genesis) as an offline vector.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { makeSubstrateVerify, verifyCheckpoint, verifyInclusion, toVerifiedEvidence } from './index.mjs';

const sha256 = (b) => createHash('sha256').update(b).digest();
const FIX = JSON.parse(readFileSync(new URL('./test-fixture.json', import.meta.url)));
const sv = makeSubstrateVerify();

test('REAL rekor.sigstore.dev anchor (captured) → final:true', async () => {
  const r = await sv(FIX.anchor, FIX.root);
  assert.equal(r.final, true);
});

test('P0 #69 A1 — fabricated treeSize=1 tree (rootHash=leaf, unsigned checkpoint) → NOT final', async () => {
  const root = 'sha256:' + 'ab'.repeat(32);
  const artifactHash = createHash('sha256').update(Buffer.from(root.slice(7), 'utf8')).digest('hex');
  const body = Buffer.from(JSON.stringify({ kind: 'hashedrekord', spec: { data: { hash: { algorithm: 'sha256', value: artifactHash } } } })).toString('base64');
  const leaf = sha256(Buffer.concat([Buffer.from([0x00]), Buffer.from(body, 'base64')]));
  const fake = {
    substrate: 'rekor', body, integratedTime: 700000000,
    inclusionProof: { logIndex: 0, treeSize: 1, hashes: [], rootHash: leaf.toString('hex'),
      checkpoint: 'rekor.sigstore.dev - 1\n1\n' + leaf.toString('base64') + '\n\n— rekor.sigstore.dev AAAAAAAA' },
  };
  const r = await sv(fake, root);
  assert.equal(r.final, false); // the checkpoint carries no valid Rekor signature
});

test('#71 P1 — the root hash present only in a COMMENT (not spec.data.hash.value) → rejected (schema-exact, not substring)', async () => {
  const a = structuredClone(FIX.anchor);
  const rootHex = FIX.root.replace(/^sha256:/, '');
  const artifactHash = createHash('sha256').update(Buffer.from(rootHex, 'utf8')).digest('hex');
  a.body = Buffer.from(JSON.stringify({ kind: 'hashedrekord', spec: { data: { hash: { algorithm: 'sha256', value: '00'.repeat(32) } }, metadata: { comment: artifactHash } } })).toString('base64');
  assert.equal(await sv(a, FIX.root), null);   // the hash is in the body, but NOT at the attested field
});

test('#71 P1 — wrong entry kind (not hashedrekord) → rejected', async () => {
  const a = structuredClone(FIX.anchor);
  const artifactHash = createHash('sha256').update(Buffer.from(FIX.root.replace(/^sha256:/, ''), 'utf8')).digest('hex');
  a.body = Buffer.from(JSON.stringify({ kind: 'rekord', spec: { data: { hash: { algorithm: 'sha256', value: artifactHash } } } })).toString('base64');
  assert.equal(await sv(a, FIX.root), null);
});

test('tampered checkpoint signature on the real anchor → NOT final', async () => {
  const a = structuredClone(FIX.anchor);
  // corrupt a byte DEEP in the base64 signature (past the 4-byte key hint the verifier skips → hits the DER sig)
  const lines = a.inclusionProof.checkpoint.split('\n');
  const si = lines.findIndex((l) => l.startsWith('— '));
  const [pre, name, sig] = lines[si].split(' ');
  const k = 16; // well past the ~6 base64 chars of the key hint
  lines[si] = [pre, name, sig.slice(0, k) + (sig[k] === 'A' ? 'B' : 'A') + sig.slice(k + 1)].join(' ');
  a.inclusionProof.checkpoint = lines.join('\n');
  assert.notEqual(a.inclusionProof.checkpoint, FIX.anchor.inclusionProof.checkpoint); // ensure we actually tampered
  const r = await sv(a, FIX.root);
  assert.equal(r.final, false);
});

test('checkpoint root ≠ inclusion-proof root → verifyCheckpoint false (signed head must match)', () => {
  const ck = FIX.anchor.inclusionProof.checkpoint;
  assert.equal(verifyCheckpoint(ck, 'sha256:' + '00'.repeat(32), FIX.anchor.inclusionProof.treeSize, undefined) , false);
});

test('entry that does not attest our root → null (claim ≠ proof)', async () => {
  const r = await sv(FIX.anchor, 'sha256:' + 'cd'.repeat(32));
  assert.equal(r, null);
});

test('verifyInclusion: single-leaf tree is self-consistent (why (3) is REQUIRED)', () => {
  const leaf = sha256(Buffer.from('x'));
  assert.equal(verifyInclusion({ leafHash: leaf, index: 0, treeSize: 1, hashes: [], rootHash: leaf.toString('hex') }), true);
});

test('P1-06 toVerifiedEvidence maps a FINAL Rekor result to typed transparency-log evidence; non-final ⇒ null', () => {
  const ev = toVerifiedEvidence('sha256:subj', { final: true, log_index: '42', time: '2026-07-01T00:00:00Z' });
  assert.equal(ev.proof_kind, 'transparency-log');
  assert.equal(ev.facts.substrate, 'rekor');
  assert.equal(ev.facts.position, '42');
  assert.equal(toVerifiedEvidence('sha256:subj', { final: false }), null);
});

test('totality (round-46 self-audit): hostile/malformed input is a structured reject, never a host throw', async () => {
  const mk = () => new Proxy([{}], { get() { throw new Error('H'); }, ownKeys() { throw new Error('H'); }, getOwnPropertyDescriptor() { throw new Error('H'); } });
  const junk = [null, undefined, {}, [], 'x', 123, mk(), { leafHash: mk(), index: 0, treeSize: 1, hashes: mk(), rootHash: 'x' }];
  for (const j of junk) assert.equal(verifyInclusion(j), false, 'verifyInclusion must return false, never throw');
  const sv = makeSubstrateVerify({ fetchImpl: async () => { throw new Error('net'); } });
  for (const j of junk) { const r = await sv(j, j); assert.ok(r === null || (r && typeof r === 'object'), 'substrateVerify must decline/structured, never host-throw'); }
});

test('SSRF/injection (round-46 self-audit): an untrusted uuid/logIndex is validated BEFORE the URL — a path/query-injection value declines, no fetch', async () => {
  const fetched = [];
  const sv = makeSubstrateVerify({ fetchImpl: async (u) => { fetched.push(String(u)); return { ok: false }; } });
  const anchor = (extra) => ({ substrate: 'rekor', ...extra });
  for (const bad of [{ uuid: '../../../admin' }, { uuid: 'evil@attacker.com' }, { uuid: 'x'.repeat(200) }, { logIndex: '1;DROP' }, { logIndex: -5 }, { logIndex: 1.5 }])
    await sv(anchor(bad), 'a'.repeat(64));
  assert.equal(fetched.filter((u) => /admin|attacker|DROP|-5|1\.5|xxxx/.test(u)).length, 0, 'a malformed uuid/logIndex must NEVER reach the fetch URL');
  await sv(anchor({ uuid: 'a'.repeat(64) }), 'b'.repeat(64));
  await sv(anchor({ logIndex: 42 }), 'b'.repeat(64));
  assert.ok(fetched.some((u) => u.includes('a'.repeat(64))) && fetched.some((u) => u.includes('logIndex=42')), 'a valid uuid/logIndex proceeds to fetch');
});
